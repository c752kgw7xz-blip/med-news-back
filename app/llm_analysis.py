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
# Mapping source → source_type DÉTERMINISTE
#
# PRINCIPE : ce dictionnaire ne contient QUE les sources dont le type est
# garanti par leur mandat institutionnel (flux officiels français/européens).
# Pour toutes les autres sources (journaux, sociétés savantes, presse médicale),
# le LLM détermine lui-même le source_type depuis le contenu de l'article :
#   - un journal peut publier une étude clinique (→ innovation) OU une guideline (→ recommandation)
#   - une société savante peut publier une RBP (→ recommandation) OU un travail de recherche (→ innovation)
# Forcer le type par la source serait un mauvais triage.
#
# Sources déterministes : textes officiels français, alertes ANSM, décisions EMA/ECDC/FDA.
# ---------------------------------------------------------------------------
SOURCE_TO_TYPE: dict[str, str] = {
    # Sources réglementaires
    "legifrance_jorf":              "reglementaire",
    "legifrance_jorf_remboursement":"reglementaire",  # JORF remboursement/nomenclature/conventions
    "piste_kali":                   "reglementaire",
    "piste_legi":                   "reglementaire",
    "piste_circ":                   "reglementaire",
    # ANSM — alertes et décisions réglementaires : toujours reglementaire par mandat
    "ansm_securite":                "reglementaire",
    "ansm_securite_med":            "reglementaire",
    "ansm_securite_dm":             "reglementaire",
    "ansm_ruptures_med":            "reglementaire",
    "ansm_ruptures_vaccins":        "reglementaire",
    "ansm_actualites":              "reglementaire",
    "bo_social":                    "reglementaire",
    # HAS — décisions formelles (accès précoce, bulletin officiel)
    "has_acces_precoces":           "reglementaire",
    "has_bo":                       "reglementaire",
    # SPF / CNOM / caisses de retraite libérales — institutionnel
    "spf_beh":                      "reglementaire",
    "cnom":                         "reglementaire",
    "ameli_medecin":                "reglementaire",  # Assurance Maladie — actualités médecins libéraux
    "carmf":                        "reglementaire",  # Caisse retraite médecins
    "carpimko":                     "reglementaire",  # Caisse retraite auxiliaires médicaux
    # EMA / ECDC — alertes et décisions réglementaires européennes
    "ema_news":                     "reglementaire",
    "ecdc_risk":                    "reglementaire",
    "ecdc_cdtr":                    "reglementaire",
    # FDA — décisions réglementaires US
    "fda_510k":                     "reglementaire",
    "fda_pma":                      "reglementaire",
    # Toutes les autres sources (journaux, sociétés savantes, presse médicale, PubMed…)
    # → source_type déterminé par le LLM depuis le contenu (voir champ "source_type" dans le JSON)
}

def get_source_type(source: str | None) -> str | None:
    """Retourne le source_type déterministe d'un candidat, ou None si le LLM doit trancher.

    Seules les sources institutionnelles (JORF, ANSM, EMA news, ECDC, FDA, CNOM…)
    ont un type garanti — elles figurent dans SOURCE_TO_TYPE.
    Pour toutes les autres (journaux, sociétés savantes, presse médicale, PubMed…),
    retourne None → le source_type est extrait du champ "source_type" dans le JSON LLM.
    """
    return SOURCE_TO_TYPE.get(source or "", None)

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
→ RÉDACTION pour articles de recherche (style journal médical spécialisé — JACC, NEJM, \
European Heart Journal) :
  resume : "Phrase 1 : énonce le résultat clinique principal en ouverture — le chiffre \
clé (réduction relative/absolue, HR/RR/OR + IC95% + p) est intégré en incise, \
jamais en tête de phrase. Exemple : 'La dapagliflozine réduit de 18 % le risque \
d'aggravation de l'IC dans l'HFpEF/HFmrEF (HR 0,82 ; IC95% 0,73–0,92 ; p<0,001).' \
Phrase 2 : design en 1 ligne (acronyme si connu, type étude, N, population, durée). \
Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude."
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
  ── Endpoints généraux (toutes spécialités) ──
  "mortality"              → mortalité toutes causes ou cause-spécifique
  "hospitalization-rate"   → taux d'hospitalisation, durée de séjour, réadmission (pédiatrie, MG, cardiologie)
  "complication-free"      → survie sans complication majeure, morbidité postopératoire
  "infection-rate"         → taux d'infection, infection-free survival (infectiologie, pédiatrie)
  "neurodevelopmental"     → développement neurocognitif, score développemental, QI, BSID (pédiatrie, néonatologie)
  "tumor-response"         → réponse tumorale (CR, PR, ORR), survie sans progression (PFS), survie globale (OS) — oncologie
  "remission-rate"         → taux de rémission clinique ou biologique (hématologie, rhumatologie, MICI)
  "pain-score"             → score douleur (EVA, NRS, WOMAC, HAQ) — rhumatologie, MPR, orthopédie
  "functional-outcome"     → score fonctionnel (Oxford Hip/Knee, Lysholm, DASH, mRS, Rankin) — orthopédie, neurologie, MPR
  "seizure-freedom"        → liberté de crises épileptiques, réduction ≥50% — neurologie
  "graft-survival"         → survie du greffon, fonction rénale post-greffe — transplantation, néphrologie
  "technical-success"      → succès technique ou anatomique
  "quality-of-life"        → qualité de vie, symptômes fonctionnels (KCCQ, NYHA, SF-36, BREAST-Q)
  ── Endpoints vasculaires & cardiaques ──
  "patency"                → perméabilité primaire/secondaire (vasculaire)
  "limb-salvage"           → sauvetage de membre (CLTI, ischémie aiguë)
  "stroke-TIA"             → AVC/AIT (carotide, aortique)
  "reintervention"         → liberté de réintervention
  "composite-MALE"         → composite d'événements membres (MALE) ou cardiovasculaires (MACE)
  "composite-MACCE"        → MACCE cardiaque : mortalité + AVC + IDM + réintervention
  "LVEF-function"          → fraction d'éjection, remodelage ventriculaire, fonction valvulaire
  "valve-durability"       → durabilité valvulaire, liberté de dégénérescence structurelle (SVD)
  "AF-recurrence"          → récidive de fibrillation atriale post-procédure
  ── Catch-all ──
  "other"                  → autre endpoint non listé
  null                     → non applicable (guideline, éditorial)

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
  ── Vasculaire / Cardiaque ──
  "ESVS"     → European Society for Vascular Surgery
  "EACTS"    → European Association for Cardio-Thoracic Surgery
  "ESC"      → European Society of Cardiology
  "AHA-ACC"  → American Heart Association / American College of Cardiology
  "STS"      → Society of Thoracic Surgeons (Amérique du Nord)
  "AATS"     → American Association for Thoracic Surgery
  "SFC"      → Société Française de Cardiologie
  "SFCTCV"   → Société Française de Chirurgie Thoracique et Cardio-Vasculaire
  "SFCV"     → Société Française de Chirurgie Vasculaire
  "SFMV"     → Société Française de Médecine Vasculaire
  ── Pédiatrie ──
  "AAP"      → American Academy of Pediatrics
  "SFP"      → Société Française de Pédiatrie
  "IPEG"     → International Pediatric Endosurgery Group
  "EUPSA"    → European Paediatric Surgeons' Association
  "ESPGHAN"  → European Society for Paediatric Gastroenterology, Hepatology and Nutrition
  "ESPID"    → European Society for Paediatric Infectious Diseases
  "GPIP"     → Groupe de Pathologie Infectieuse Pédiatrique
  ── Oncologie ──
  "ESMO"     → European Society for Medical Oncology
  "ASCO"     → American Society of Clinical Oncology
  ── Rhumatologie ──
  "EULAR"    → European Alliance of Associations for Rheumatology
  "ACR"      → American College of Rheumatology
  ── Neurologie ──
  "EAN"      → European Academy of Neurology
  "AAN"      → American Academy of Neurology
  ── Pneumologie ──
  "ERS"      → European Respiratory Society
  "ATS"      → American Thoracic Society
  ── Urologie ──
  "EAU"      → European Association of Urology
  ── Gastro-entérologie / Hépatologie ──
  "ECCO"     → European Crohn's and Colitis Organisation
  "EASL"     → European Association for the Study of the Liver
  ── Orthopédie ──
  "EFORT"    → European Federation of National Associations of Orthopaedics and Traumatology
  ── Institutionnel FR ──
  "HAS"      → Haute Autorité de Santé
  ── Catch-all ──
  "autre"    → tout autre organisme non listé
  null       → non applicable (étude de recherche primaire, pas un guideline)

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

━━ CHAMPS CHIRURGIE PÉDIATRIQUE — remplir seulement si specialty_hint = chirurgie-pediatrique ━━

"pediatric_domain" — domaine chirurgical pédiatrique concerné :
  "chirurgie-neonatale"          → malformations congénitales néonatales : atrésie œsophagienne,
                                    hernie diaphragmatique congénitale (HDC), gastroschisis, omphalocèle,
                                    atrésie duodénale/jéjunale/iléale, malrotation intestinale, entérocolite
                                    nécrosante (NEC), imperforation anale
  "chirurgie-digestive-pediatrique" → appendicite aiguë, invagination intestinale aiguë, maladie de Hirschsprung,
                                    volvulus, RGO/fundoplicature, sténose hypertrophique du pylore,
                                    atrésie biliaire, kyste du cholédoque, polypes, colites
  "urologie-pediatrique"         → hypospadias, cryptorchidie, reflux vésico-urétéral (RVU), valves de l'urètre
                                    postérieur (VUP), hydronéphrose/sténose jonction pyélo-urétérale (SJPU),
                                    extrophie vésicale, duplicités urétérales, lithiase urinaire pédiatrique
  "oncologie-pediatrique"        → néphroblastome (tumeur de Wilms), neuroblastome, hépatoblastome,
                                    rhabdomyosarcome, tératome sacrococcygien, tumeur stromale pédiatrique
  "chirurgie-thoracique-pediatrique" → malformation adénomatoïde kystique (CPAM), emphysème lobaire congénital,
                                    séquestration bronchopulmonaire, atrésie trachéale, pyothorax, pectus
                                    excavatum/carinatum (Nuss, Ravitch)
  "hernie-paroi-pediatrique"     → hernie inguinale, hydrocèle communicante, hernie ombilicale, hernie para-
                                    ombilicale, éventration congénitale
  "traumatologie-pediatrique"    → traumatismes abdominaux fermés (rate, foie, pancréas), damage control
                                    pédiatrique, traumatisme rate (splénectomie vs conservation)
  "chirurgie-mini-invasive-pediatrique" → laparoscopie pédiatrique (appendicectomie, fundoplicature, Nissen),
                                    thoracoscopie pédiatrique (CPAM, atrésie trachéale, empyème),
                                    robotique pédiatrique, SILS/notes pédiatrique
  "nutrition-perioperatoire-pediatrique" → nutrition parentérale longue durée, intestin court, stomies pédiatriques,
                                    réhabilitation améliorée en chirurgie pédiatrique (ERACS)

"pediatric_procedure" — technique ou procédure principale :
  Néonatal    : "anastomose-atrésie-oesophagienne"|"technique-Foker-long-gap"|"réparation-HDC"|
                "gastroschisis-silo"|"iléostomie-NEC"|"anoplastie-imperforation"|"Ladd-malrotation"
  Digestif    : "appendicectomie-laparoscopique"|"appendicectomie-ouverte"|"pyloromyotomie-Fredet"|
                "Soave-Hirschsprung"|"Duhamel-Hirschsprung"|"TERPT"|"fundoplicature-Nissen"|
                "Kasai-atrésie-biliaire"|"invagination-désinvagination"
  Urologie    : "orchidopexie-1-temps"|"orchidopexie-Fowler-Stephens-2-temps"|"hypospadias-TIP-Snodgrass"|
                "hypospadias-Mathieu"|"pyéloplastie-Andersen-Hynes"|"réimplantation-urétérale-Cohen"|
                "STING-endoscopique-RVU"|"valve-urètre-postérieur-résection"
  Oncologie   : "nephrectomie-Wilms"|"exérèse-neuroblastome"|"hépatectomie-hépatoblastome"|
                "résection-tératome-sacrococcygien"
  Thoracique  : "résection-CPAM-thoracoscopique"|"lobectomie-thoracoscopique-pédiatrique"|
                "Nuss-pectus-excavatum"|"Ravitch-pectus"
  Autre       : "hernie-inguinale-ouverte"|"hernie-inguinale-PIRS-laparoscopique"|
                "splénectomie-partielle"|"stomie-pédiatrique"|"autre"

Standards actuels — CHIRURGIE PÉDIATRIQUE (specialty_hint = chirurgie-pediatrique) :
  • Appendicite aiguë pédiatrique : laparoscopie = standard (3 trocarts) ; antibiothérapie seule
    non recommandée en routine chez l'enfant (débat en cours) — APSA/IPEG 2023
  • Sténose hypertrophique du pylore : pyloromyotomie de Fredet-Ramstedt (ouverte ou laparoscopique)
    = standard ; équivalents selon RCPCH/AAP 2019
  • Hernie inguinale pédiatrique : ligature haute du sac en chirurgie ouverte = standard ;
    PIRS (laparoscopique) pour bilatéralité ou récidive — IPEG guidelines 2022
  • Atrésie œsophagienne : anastomose primaire si diastasis < 3 cm ; technique de Foker si long gap —
    EUPSA/ESPES consensus 2022
  • HDC (hernie diaphragmatique congénitale) : stabilisation pré-opératoire obligatoire
    (HFOV/NO/ECMO si nécessaire) avant réparation ; voie laparoscopique controversée si défect > 50% —
    CDH Study Group / EUPSA
  • Maladie de Hirschsprung : TERPT (transanal endorectal pull-through) = standard actuel ;
    Duhamel ou Soave laparoscopique selon équipe — APSA/EUPSA 2020
  • Cryptorchidie : orchidopexie avant 18 mois si non palpable ; Fowler-Stephens 2 temps si très haut —
    EAU Pediatric/AAP 2017
  • Reflux vésico-urétéral : surveillance + prophylaxie grades I-III ; réimplantation (Cohen/STING)
    grades IV-V — EAU Pediatric 2023
  • Néphroblastome (Wilms) : chimiothérapie néo-adjuvante pré-opératoire = standard SIOP (Europe) ;
    chirurgie d'emblée selon COG (USA) — SIOP WT 2016 protocol
  → Un RCT ou guideline qui invalide l'un de ces standards = paradigm_shift:true

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
   - exercice       : Tout ce qui touche à l'exercice professionnel et à la gestion du \
cabinet libéral — qu'il soit médical au sens strict ou administratif/entrepreneurial. \
Le médecin libéral est un chef d'entreprise : tout ce qui impacte sa pratique compte. \
\
     Exemples MÉDICAUX : convention médicale, installation, déserts médicaux, gardes, \
télémédecine, statut libéral, groupement (MSP, CPTS, GHT), logiciels métier (LAP, DMP, \
DxCare…) ; CCAM, NGAP, NABM, tarifs, cotations, honoraires, remboursement d'actes ; \
formation médicale continue (DPC), certifications, accréditations, obligations déclaratives. \
\
     Exemples ADMINISTRATIFS ET FINANCIERS (non strictement médicaux mais essentiels) : \
statut juridique du cabinet (BNC, SELARL, SCP, SCM) ; fiscalité médicale, régime fiscal ; \
protection sociale des libéraux (retraite CARMF/CARCDSF/CARPV, prévoyance, arrêt maladie) ; \
cotisations URSSAF, charges sociales ; réforme de la convention ou de la protection sociale \
impactant les revenus ; gestion administrative du cabinet (secrétariat, location local, \
gestion des impayés CPAM) ; responsabilité civile professionnelle, assurance ; \
droit du travail si le praticien emploie du personnel ; réglementation comptable.

   RÈGLES DE DISCRIMINATION (prioritaires sur les définitions ci-dessus) :
   - Molécule / DCI / spécialité pharmaceutique nommée / AMM → 'therapeutique'
   - Équipement, matériel, appareil, dispositif médical (y compris imagerie) → 'therapeutique'
   - Logiciel métier santé (LAP, DxCare, NETSoins, Cortexte, DMP) → 'exercice'
   - Facturation, cotation CCAM/NGAP/NABM, honoraires, avenant tarifaire → 'exercice'
   - Dépistage, vaccination, alerte épidémique, plan national → 'clinique'
   - Retraite CARMF, protection sociale libérale, URSSAF médecin → 'exercice'
   - Statut juridique cabinet, fiscalité BNC/SELARL → 'exercice'
   - Responsabilité civile professionnelle, assurance médecin → 'exercice'

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
       Revalorisation cotisation CARMF      → exercice
       Réforme protection sociale libérale  → exercice
       Passage en SELARL : avantages fiscaux→ exercice
       Gestion impayés CPAM en cabinet      → exercice

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

8. TYPE DE SOURCE (source_type) — Détermine la nature du contenu, indépendamment \
de qui le publie. Une société savante peut publier une étude clinique ET une guideline ; \
un journal peut contenir un article original ET un consensus. Juge sur le CONTENU.

   "recommandation" : guideline officielle, recommandation de bonne pratique (RBP), \
RFE, consensus de société savante, référentiel de prise en charge, avis d'expert \
structuré émis par une organisation médicale. Reconnaissable à : la source est \
nommée comme auteur du texte ("ESVS recommande…", "HAS publie…", "consensus SFAR…") ; \
pas de design d'étude primaire, pas de nouvelles données — c'est une synthèse normative.

   "innovation" : étude originale de recherche clinique (RCT, cohorte, registre, \
méta-analyse, série de cas), résultat de recherche, nouvelle technique en évaluation, \
nouvelles données probantes sur un traitement ou une procédure. Reconnaissable à : \
design d'étude explicite, population, critère de jugement, résultats statistiques, \
auteurs de centres hospitaliers ou universitaires.

   "reglementaire" : texte réglementaire officiel (loi, décret, arrêté, circulaire), \
décision administrative formelle, alerte de sécurité officielle d'une autorité \
(retrait produit, rappel de lot, suspension AMM), autorisation ou modification d'AMM. \
RÉSERVÉ aux contenus émanant directement d'une autorité institutionnelle (JORF, ANSM, \
EMA, FDA, CNOM) — si le texte provient d'un journal ou d'une société savante qui \
commente une décision réglementaire, classe plutôt en "recommandation" ou "innovation".

   Exemples :
     Article EJVES sur outcomes EVAR n=420 (RCT)     → "innovation"
     Guidelines ESVS 2024 sur anévrisme aortique      → "recommandation"
     ESVS commentary on new ESC guidelines            → "recommandation"
     JAMA Surgery — essai randomisé appendicite       → "innovation"
     Annals of Surgery — méta-analyse hernie inguinal → "innovation"
     SFAR — recommandations formalisées d'experts     → "recommandation"
     SFAR — étude observationnelle sur prémédication  → "innovation"
     Décret JORF parcours de soins cancer             → "reglementaire"
     Alerte ANSM garrot chirurgical                   → "reglementaire"
     Vascular News — compte-rendu résultats BEST-CLI  → "innovation"
     Vascular News — synthèse guidelines SVS 2024     → "recommandation"

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
    # PubMed — chirurgie vasculaire
    "pubmed_jvs", "pubmed_ejves", "pubmed_jet", "pubmed_ann_vasc_surg",
    # PubMed — chirurgie cardiaque
    "pubmed_jtcvs", "pubmed_ejcts", "pubmed_ann_thorac_surg",
    "pubmed_circulation_card", "pubmed_jacc_card", "pubmed_jacc_interv",
    "pubmed_eur_heart_j", "pubmed_jhlt", "pubmed_eurointerv", "pubmed_circ_heart_fail",
    # PubMed — chirurgie orthopédique
    "pubmed_jbjs", "pubmed_bone_joint_j", "pubmed_corr", "pubmed_jarthroplasty",
    "pubmed_kssta", "pubmed_acta_orthop", "pubmed_otsr",
    "pubmed_ajsm", "pubmed_arthroscopy", "pubmed_jses", "pubmed_spine",
    "pubmed_j_orthop_trauma", "pubmed_int_orthop", "pubmed_arch_orthop_trauma",
    # PubMed — chirurgie plastique & reconstructrice
    "pubmed_prs", "pubmed_jpras", "pubmed_asj", "pubmed_ann_plast_surg",
    "pubmed_jhs_am", "pubmed_jhs_eur", "pubmed_jrms", "pubmed_microsurgery",
    "pubmed_burns", "pubmed_acpe", "pubmed_prs_global_open", "pubmed_wound_repair",
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
    specialty_hint: str | None = None,
) -> str:
    """
    source_hint    : indication sur la provenance pour contextualiser Claude.
    is_innovation  : True → ajoute le bloc evidence_json dans le template JSON.
    is_press       : True → source presse médicale (pas d'evidence_json, filtre différent).
    specialty_hint : spécialité de la source → adapte les champs evidence_json spécifiques.
    """
    source_line = f"\nSOURCE : {source_hint}" if source_hint else ""
    content_section = ""
    if content and len(content.strip()) > 50:
        excerpt = content.strip()[:3000]
        content_section = f"\n\nEXTRAIT :\n{excerpt}"

    evidence_block = ""
    # is_press sources : pas de evidence_json — le journaliste ne fournit pas de design d'étude
    if is_innovation and not is_press:
        # Champs spécifiques à la spécialité — insérés après primary_endpoint_met
        _SPE_FIELDS: dict[str, str] = {
            "chirurgie-vasculaire": (
                '    "vascular_domain": "<aorte-abdominale|aorte-thoracique|aorte-thoraco-abdominale|carotide-TSA|AOMI-femoro-poplite|AOMI-sous-poplite|ischemie-aigue-membre|veineux-TVP-EP|veineux-varices|acces-vasculaire-dialyse|renovasculaire|traumatique|multi-domaine|non-vasculaire>",\n'
                '    "intervention_type": "<EVAR|TEVAR|FEVAR-BEVAR|CAS|TCAR|PTA-stent|DCB|atherectomie|thrombectomie-mecanique|thrombolyse-CDT|ablation-thermique|ablation-non-thermique|pontage|endarterectomie|reparation-ouverte|hybride|anticoagulation|antiplatelet|traitement-medical|strategie-diagnostique|surveillance|multi-modalite|autre>",\n'
            ),
            "chirurgie-cardiaque": (
                '    "cardiac_domain": "<coronaire-CABG|valvulaire-aortique|valvulaire-mitral|valvulaire-tricuspide|aorte-ascendante-arche|structural-heart|LVAD-assistance-circ|arythmie-Maze|congenital-adulte|transplantation-cardiaque|perikarde-tumeur|multi-domaine-cardiaque|non-cardiaque>",\n'
                '    "cardiac_procedure": "<SAVR|TAVI-TAVR|Ross|Bentall|plastie-mitrale|remplacement-mitral|MitraClip-TEER|remplacement-tricuspide|plastie-tricuspide|CABG-CEC|CABG-off-pump|CABG-vs-PCI|remplacement-aorte-ascendante|intervention-arche|LVAD|ECMO-VA|fermeture-FOP-CIA|LAA-occlusion|Maze-Cox|cryoablation-epikardique|transplantation|autre>",\n'
            ),
            "chirurgie-plastique": (
                '    "plastic_domain": "<reconstruction-mammaire|chirurgie-esthetique|microchirurgie|chirurgie-main|brulures|oncoplastique|cicatrices-cheloïdes|lipofilling|malformations-congenitales|couverture-cutanee|tete-cou-reconstruction|implants-protheses-mammaires>",\n'
                '    "plastic_procedure": "<DIEP|TRAM|Grand-Dorsal-implant|implant-seul|expandeur-implant|lipofilling-sein|rhinoplastie|mammoplastie-augmentation|mammoplastie-reduction|abdominoplastie|liposuccion|lambeau-libre-ALT|replantation-digitale|LVA-lymphatique|VLNT|suture-tendon|greffe-nerveuse|arthroplastie-digitale|aponevrotomie-Dupuytren|liberation-canal-carpien|excision-autogreffe|substitut-Integra|RECELL|lambeau-local-regional|traitement-cheloïdes|autre>",\n'
            ),
            "chirurgie-pediatrique": (
                '    "pediatric_domain": "<chirurgie-neonatale|chirurgie-digestive-pediatrique|urologie-pediatrique|oncologie-pediatrique|chirurgie-thoracique-pediatrique|hernie-paroi-pediatrique|traumatologie-pediatrique|chirurgie-mini-invasive-pediatrique|nutrition-perioperatoire-pediatrique>",\n'
                '    "pediatric_procedure": "<anastomose-atrésie-oesophagienne|réparation-HDC|gastroschisis-silo|iléostomie-NEC|Ladd-malrotation|appendicectomie-laparoscopique|appendicectomie-ouverte|pyloromyotomie-Fredet|Soave-Hirschsprung|Duhamel-Hirschsprung|TERPT|fundoplicature-Nissen|Kasai-atrésie-biliaire|invagination-désinvagination|orchidopexie-1-temps|orchidopexie-Fowler-Stephens-2-temps|hypospadias-TIP-Snodgrass|pyéloplastie-Andersen-Hynes|réimplantation-urétérale-Cohen|STING-endoscopique-RVU|nephrectomie-Wilms|résection-CPAM-thoracoscopique|Nuss-pectus-excavatum|hernie-inguinale-PIRS-laparoscopique|autre>",\n'
            ),
            "pediatrie": (
                '    "pediatric_domain": "<infectiologie-pediatrique|pneumologie-pediatrique|neonatologie|allergologie-pediatrique|neurologie-pediatrique|endocrinologie-pediatrique|gastro-pediatrique|cardiologie-pediatrique|nephrologie-pediatrique|dermatologie-pediatrique|vaccination|developpement-croissance|urgences-pediatriques>",\n'
            ),
        }
        _spe_lines = _SPE_FIELDS.get(specialty_hint or "", "")
        evidence_block = (
            ',\n'
            '  "evidence_json": {{\n'
            '    "study_design": "<RCT|meta-analysis|registry|prospective-cohort|retrospective-cohort|case-series|guideline|regulatory-decision|technique-paper|review|editorial>",\n'
            '    "phase": <"1"|"2"|"3"|"4"|null>,\n'
            '    "n_patients": <int|null>,\n'
            '    "multicentre": <true|false|null>,\n'
            '    "follow_up_months": <int|null>,\n'
            '    "primary_endpoint": "<mortality|hospitalization-rate|complication-free|neurodevelopmental|infection-rate|tumor-response|remission-rate|pain-score|functional-outcome|seizure-freedom|graft-survival|patency|limb-salvage|stroke-TIA|reintervention|composite-MALE|composite-MACCE|LVEF-function|valve-durability|AF-recurrence|technical-success|quality-of-life|other|null>",\n'
            '    "primary_endpoint_met": <true|false|null>,\n'
            + _spe_lines +
            '    "comparator_type": "<vs-chirurgie-ouverte|vs-endovasculaire-autre|vs-traitement-medical|vs-placebo|vs-standard-of-care|aucun|null>",\n'
            '    "clinical_maturity": "<exploratory|preliminary|pivotal|confirmatory|practice-defining|regulatory-event>",\n'
            '    "actionability_horizon": "<immediate|1-3y|3-5y|exploratory>",\n'
            '    "regulatory_milestone": <"CE_mark"|"AMM_europe"|"FDA_approval"|"remboursement_HAS"|"CNAM_accord"|"guideline_update"|"autorisation_temporaire"|null>,\n'
            '    "guideline_body": <"ESVS"|"EACTS"|"ESC"|"HAS"|"AHA-ACC"|"STS"|"AATS"|"SFC"|"SFCTCV"|"SFCV"|"SFMV"|"AAP"|"SFP"|"IPEG"|"EUPSA"|"ESPGHAN"|"ESPID"|"GPIP"|"ESMO"|"ASCO"|"EULAR"|"ACR"|"EAN"|"AAN"|"ERS"|"ATS"|"EAU"|"ECCO"|"EASL"|"EFORT"|"autre"|null>,\n'
            '    "guideline_grade": <"IA"|"IB"|"IIaA"|"IIaB"|"IIbA"|"IIbB"|"III"|null>,\n'
            '    "paradigm_shift": <bool>,\n'
            '    "negative_result": <bool>,\n'
            '    "safety_signal": <bool>\n'
            '  }}'
        )

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
  "source_type": "<recommandation|innovation|reglementaire>",
  "tri_json": {{
    "titre_court": "<≤12 mots>",
    "resume": "<2-3 phrases concrètes selon nature du texte>",
    "impact_pratique": "<1 phrase : action précise à faire / retenir>",
    "nature": "<ARRETE|DECRET|LOI|ORDONNANCE|RECOMMANDATION|ALERTE|AVENANT|CIRCULAIRE|ETUDE|AUTRE>",
    "date_publication": "{date_pub}",
    "date_entree_en_vigueur": "<YYYY-MM-DD — date d'application effective, différente de date_publication si précisée dans le texte>"
  }},
  "lecture_json": {{
    "points_cles": ["<bullet 1 — fait chiffré ou décision clé>", "<bullet 2>", "<bullet 3>"],
    // obligatoire : 3 bullets minimum, 5 maximum — jamais vide ni tableau à un seul élément
    "texte_long": "<~200 mots — développement distinct du resume : contexte de l'étude, détail des résultats secondaires, comparaison au standard actuel, limites principales>",
    "references": ["<NOR, ref légale, numéro AMM, PMID...>"]
  }}{evidence_block}
}}
"""

# ---------------------------------------------------------------------------
# Mapping source → hint contextuel pour Claude
# ---------------------------------------------------------------------------

SOURCE_HINTS: dict[str, str] = {
    # Sources réglementaires
    "legifrance_jorf":                "JORF — texte réglementaire (loi, décret, arrêté)",
    "legifrance_jorf_remboursement":  "JORF — arrêté/décret remboursement : inscription/modification liste spécialités pharmaceutiques remboursables, LPP, tarifs de responsabilité, prix de cession, convention médicale ou avenant, nomenclature NGAP/CCAM/NABM, accès précoce",
    "piste_kali":                     "Convention collective santé — accord relatif aux salariés du secteur santé (assistants médicaux, secrétaires, personnel paramédical) : salaires, prévoyance, frais de santé, classifications",
    "piste_legi":            "Code de la santé publique — modification de texte codifié (CSP, CSS, CASF)",
    "piste_circ":            "Circulaire ou instruction ministérielle — directive santé ou social",
    "ansm_securite":         "ANSM — Information de sécurité (pharmacovigilance, matériovigilance)",
    "ansm_securite_med":     "ANSM — Alerte sécurité médicament (retrait AMM, contre-indication, restriction)",
    "ansm_securite_dm":      "ANSM — Alerte matériovigilance dispositif médical (implants, instruments chirurgicaux, DM soins infirmiers)",
    "ansm_ruptures_med":     "ANSM — Rupture ou tension d'approvisionnement médicament",
    "ansm_ruptures_vaccins": "ANSM — Disponibilité vaccins",
    "ansm_actualites":       "ANSM — Point d'information ou communiqué (pharmacovigilance, signal émergent, bilan)",
    "bo_social":             "Bulletin officiel ministères sociaux — circulaire ou instruction ministère Santé",
    # HAS — sources complémentaires
    "has_acces_precoces":    "HAS — Décision d'accès précoce (ex-ATU cohorte) : médicament innovant autorisé avant AMM pour pathologie grave sans alternative — le médecin peut prescrire dès la publication",
    "has_bo":                "HAS — Bulletin officiel : décision formelle numérotée (accès précoce, avis vaccin, certification, CEESP) — complémentaire aux flux has_rbp et has_ct",
    # INCa
    "inca_recommandations":  "INCa — Recommandation ou référentiel national en oncologie (cancers solides, hémato, soins de support)",
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
    "sfpediatrie":                  "SFP — Recommandation pédiatrie",
    "pubmed_pediatrics":            "Pediatrics (AAP)",
    "pubmed_pediatrics_guidelines": "Pediatrics AAP — Clinical Practice Guidelines",
    "pubmed_jama_peds":             "JAMA Pediatrics",
    "pubmed_arch_dis_child":        "Archives of Disease in Childhood",
    "pubmed_eur_j_pediatr":         "European Journal of Pediatrics",
    "sfnn":              "SFN — Recommandation néonatalogie",
    "sfsp":              "SFSP — Recommandation santé publique et prévention",
    "sfdermato":         "SFDermato — Recommandation dermatologie",
    "sfo":               "SFO — Recommandation ophtalmologie",
    "afsos":             "AFSOS — Recommandation soins oncologiques de support",
    "sfh":               "SFH — Recommandation hématologie",
    "sfr_radiologie":    "SFR — Recommandation radiologie diagnostique et interventionnelle",
    "sofcot":            "SOFCOT — Recommandation chirurgie orthopédique et traumatologique",
    "sofcpre_plastique":  "SOFCPRE — Recommandation chirurgie plastique reconstructrice et esthétique",
    "sfcp":               "SFCP — Recommandation chirurgie pédiatrique",
    "sfcp_pediatrique":   "SFCP — Recommandation chirurgie pédiatrique (site SFCP)",
    "sniil":             "SNIIL — Recommandation et actualités infirmiers libéraux",
    "ffmkr":             "FFMKR — Recommandation kinésithérapie et rééducation",
    "cnsf":              "CNSF — Recommandation sages-femmes",
    "sfbc":              "SFBC — Recommandation biologie clinique et médicale",
    "fspf":              "FSPF — Actualités réglementaires pharmaciens d'officine",
    # Nouvelles sources institutionnelles — audit mars 2026
    "has_ct":  "HAS Commission de la Transparence — Avis remboursement médicament (ASMR/SMR)",
    "has_dm":  "HAS — Avis sur les dispositifs médicaux (admission remboursement, conditions utilisation)",
    "spf_beh": "Santé publique France — Article épidémiologique (BEH, alerte sanitaire, vaccination)",
    "cnom":          "CNOM (Ordre des Médecins) — Déontologie médicale, réglementation exercice libéral",
    "ameli_medecin": "Assurance Maladie (ameli.fr) — Actualités médecins libéraux : convention médicale, honoraires, FMT/Donum, remboursements CCAM, téléconsultation, nouveaux actes, outils praticiens",
    "carmf":         "CARMF (Caisse Autonome de Retraite des Médecins de France) — Retraite, cotisations, PSS, ASV, prévoyance médecins libéraux",
    "carpimko":      "CARPIMKO (Caisse de Retraite des auxiliaires médicaux libéraux) — Retraite, cotisations, assiette sociale infirmiers, kinésithérapeutes, pédicures-podologues, orthophonistes, orthoptistes",
    # ── Sociétés savantes françaises (RSS + scraping) ─────────────────────
    "gpip":            "GPIP — Groupe de Pathologie Infectieuse Pédiatrique : recommandations antibiothérapie, vaccination, protocoles infectiologie pédiatrique",
    # ── Sources européennes (agences réglementaires EU) ───────────────────
    "ema_news":        "EMA — Alerte ou décision de sécurité européenne : retrait AMM, suspension, restriction d'indication, DHPC diffusé par l'EMA",
    "ema_guidelines":  "EMA — Guideline scientifique européen sur l'évaluation des médicaments (ICH, CHMP) — impact sur les standards d'autorisation",
    "ema_new_medicines": "EMA — Nouvelle AMM européenne (CHMP opinion positive) : médicament human nouvellement autorisé dans l'UE",
    "ecdc_risk":       "ECDC — Évaluation du risque épidémique européen : menace infectieuse émergente, épidémie transfrontalière, pathogène résistant",
    "ecdc_guidance":   "ECDC — Recommandation technique européenne de prévention et contrôle des infections (vaccination, screening, isolement)",
    "ecdc_cdtr":       "ECDC — CDTR (Communicable Disease Threats Report) : surveillance hebdomadaire des menaces infectieuses en Europe",
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
    "pubmed_prs_global_open":  "Plastic and Reconstructive Surgery Global Open (ASPS open access) — Essai clinique, méta-analyse ou étude comparative en chirurgie plastique, reconstructrice et esthétique (companion open-access de PRS)",
    "pubmed_wound_repair":     "Wound Repair and Regeneration (WRR/Wiley) — Essai clinique ou méta-analyse sur cicatrisation, substituts cutanés (Integra, MatriDerm, NPWT, RECELL), brûlures, plaies chroniques, techniques de greffe",
    "pubmed_prs_guidelines":   "PRS Guidelines ASPS — Recommandation ou consensus ASPS en chirurgie plastique : sécurité implants mammaires, BIA-ALCL, reconstruction mammaire, techniques esthétiques",
    "pubmed_jpras_guidelines": "JPRAS Guidelines BAPRAS/ESPRAS — Recommandation européenne chirurgie plastique : reconstruction, brûlures, main, techniques esthétiques",
    # ── PubMed — chirurgie pédiatrique ────────────────────────────────────────
    "pubmed_jps":              "Journal of Pediatric Surgery (JPS/IPEG/APSA) — Essai clinique, méta-analyse ou étude multicentrique en chirurgie pédiatrique : malformations congénitales, laparoscopie, appendicite, hernie, sténose pylorique, oncologie pédiatrique",
    "pubmed_psi":              "Pediatric Surgery International (PSI/EUPSA) — Études multicentriques européennes et asiatiques en chirurgie pédiatrique : chirurgie néonatale, laparoscopie pédiatrique, urologie pédiatrique",
    "pubmed_ejps":             "European Journal of Pediatric Surgery (EJPS/EUPSA) — Essai clinique ou méta-analyse en chirurgie pédiatrique européenne : atrésie œsophagienne, hernie diaphragmatique, Hirschsprung, oncologie pédiatrique",
    "pubmed_semin_pediatr_surg":"Seminars in Pediatric Surgery (SPS) — Guideline ou consensus thématique en chirurgie pédiatrique (IPEG, APSA, CDH Study Group)",
    "pubmed_jps_guidelines":   "JPS Guidelines IPEG/APSA/EUPSA — Recommandation ou position statement de société savante en chirurgie pédiatrique publiée dans le Journal of Pediatric Surgery",
    "pubmed_jpu":              "Journal of Pediatric Urology (JPU/ESPU/EAU) — Essai clinique, méta-analyse ou étude multicentrique en urologie pédiatrique : hypospadias, cryptorchidie, RVU, VUP, SJPU, lithiase, neurologie urinaire pédiatrique",
    "pubmed_jpu_guidelines":   "JPU Guidelines EAU Pediatric / ESPU — Recommandation ou position statement EAU Pediatric Urology / ESPU en urologie pédiatrique publiée dans le Journal of Pediatric Urology",
    "eupsa_pediatrique":       "EUPSA — Guideline ou position statement de l'European Paediatric Surgeons' Association en chirurgie pédiatrique",
}

# ---------------------------------------------------------------------------
# Mapping source → spécialité principale (pour sélection du prompt dédié)
# Seules les sources mono-spécialité ont une entrée ici.
# Les sources multi-spécialités (JORF, HAS, JAMA…) n'ont PAS d'entrée →
# le prompt générique est utilisé, la spécialité est déterminée par le LLM.
# ---------------------------------------------------------------------------
SOURCE_SPECIALTY_HINTS: dict[str, str] = {
    # ── Chirurgie vasculaire ───────────────────────────────────────────────
    "jvs_rss":                 "chirurgie-vasculaire",  # RSS JVS (SVS/Elsevier, IF ~4)
    "pubmed_jvs":              "chirurgie-vasculaire",
    # ── Presse clinique Healio — 15 spécialités ────────────────────────────
    # healio_hemato_onco absent → prompt générique (multi-spé : hémato + onco)
    "healio_cardio":           "cardiologie",
    "healio_nephro":           "nephrologie",
    "healio_infect":           "infectiologie",
    "healio_rhuma":            "rhumatologie",
    "healio_endo":             "endocrinologie",
    "healio_ophtalmo":         "ophtalmologie",
    "healio_gastro":           "gastro-enterologie",
    "healio_psy":              "psychiatrie",
    "healio_neuro":            "neurologie",
    "healio_ortho":            "chirurgie-orthopedique",
    "healio_pulmo":            "pneumologie",
    "healio_derma":            "dermatologie",
    "healio_pedia":            "pediatrie",
    "healio_geria":            "geriatrie",
    # ── Presse clinique sociétés savantes ─────────────────────────────────
    "aans_news":               "neurochirurgie",
    "aaos_news":               "chirurgie-orthopedique",
    "aga_news":                "gastro-enterologie",
    "psychiatric_times":       "psychiatrie",
    "urology_times":           "urologie",
    # ── ENTtoday + MedPage Today — gaps presse clinique (avril 2026) ──────
    "enttoday":                    "orl",
    "medpage_obgyn":               "gynecologie",
    "medpage_emergency":           "medecine-urgences",
    "medpage_anesthesiology":      "anesthesiologie",
    "medpage_radiology":           "radiologie",
    # medpage_surgery absent → comportement générique (multi-spé chirurgicale)
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
    # ── Chirurgie thoracique ───────────────────────────────────────────────────
    "jto_rss":                    "chirurgie-thoracique",  # RSS JTO (IASLC/Elsevier, IF ~20)
    "pubmed_jto":                 "chirurgie-thoracique",  # JTO — IASLC
    "pubmed_lung_cancer_thorac":  "chirurgie-thoracique",  # Lung Cancer — NSCLC résécable
    "pubmed_dis_esophagus":       "chirurgie-thoracique",  # Diseases of the Esophagus — ISDE
    "pubmed_icvts":               "chirurgie-thoracique",  # ICVTS — EACTS
    "pubmed_semin_thorac":        "chirurgie-thoracique",  # Seminars Thoracic & Cardiovasc Surg
    "pubmed_chest":               "chirurgie-thoracique",  # Chest — ACCP
    "pubmed_thorax_bts":          "chirurgie-thoracique",  # Thorax — BTS/BMJ
    "pubmed_ejso_thorac":         "chirurgie-thoracique",  # EJSO — filtre thoracique
    "pubmed_ann_surg_oncol_thorac":"chirurgie-thoracique", # Ann Surg Oncol — filtre thoracique
    "pubmed_jtcvs_thorac":        "chirurgie-thoracique",  # JTCVS — filtre thoracique
    "pubmed_ests_guidelines":     "chirurgie-thoracique",  # ESTS Guidelines via EJCTS
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
    "pubmed_prs_global_open":      "chirurgie-plastique",
    "pubmed_wound_repair":         "chirurgie-plastique",
    "pubmed_prs_guidelines":      "chirurgie-plastique",
    "pubmed_jpras_guidelines":    "chirurgie-plastique",
    # ── Chirurgie pédiatrique ──────────────────────────────────────────────────
    "pubmed_jps":               "chirurgie-pediatrique",
    "pubmed_psi":               "chirurgie-pediatrique",
    "pubmed_ejps":              "chirurgie-pediatrique",
    "pubmed_semin_pediatr_surg":"chirurgie-pediatrique",
    "pubmed_jps_guidelines":    "chirurgie-pediatrique",
    "sfcp_pediatrique":         "chirurgie-pediatrique",
    "pubmed_jpu":               "chirurgie-pediatrique",
    "pubmed_jpu_guidelines":    "chirurgie-pediatrique",
    "eupsa_pediatrique":              "chirurgie-pediatrique",
    # ── Pédiatrie générale ──────────────────────────────────────────────────
    "bmj_adc":                        "pediatrie",  # RSS Archives of Disease in Childhood / RCPCH (IF ~5)
    # eclinmedicine → spécialité variable, absent du dict → prompt générique (comportement voulu)
    "pubmed_pediatrics":              "pediatrie",
    "pubmed_pediatrics_guidelines":   "pediatrie",
    "pubmed_jama_peds":               "pediatrie",
    "pubmed_arch_dis_child":          "pediatrie",
    "pubmed_eur_j_pediatr":           "pediatrie",
    "pubmed_lancet_child":            "pediatrie",
    "pubmed_j_pediatr":               "pediatrie",
    "pubmed_arch_pediatr":            "pediatrie",
    "pubmed_pidj":                    "pediatrie",
    "pubmed_acta_paediatr":           "pediatrie",
    "pubmed_pediatr_neurol":          "pediatrie",
    "sfpediatrie":                    "pediatrie",
    "gpip":                           "pediatrie",
    "eap_pediatrie":                  "pediatrie",
    # ── Sociétés savantes françaises — manquantes (audit avril 2026) ──────────
    # Médecine générale
    "cnge":                           "medecine-generale",   # CNGE — médecins généralistes
    "sfms":                           "medecine-du-sport",   # SFMS — médecine du sport et de l'exercice
    # Médecine interne & addictologie
    "snfmi":                          "medecine-interne",    # SNFMI — médecine interne
    "sfalcoologie":                   "addictologie",        # SFAL — alcoologie et addictologie
    # Cardiologie
    "sfhta":                          "cardiologie",         # SFHTA — hypertension artérielle
    # Neurologie & neurochirurgie
    "sfn":                            "neurologie",          # SFN — Société Française de Neurologie
    "sfnc":                           "neurochirurgie",      # SFNC — neurochirurgie
    # Endocrinologie & diabétologie
    "sfendocrino":                    "endocrinologie",      # SFE — endocrinologie
    "sfdiabete":                      "endocrinologie",      # SFD — diabétologie
    # Gastro-entérologie & hépatologie (déjà: snfge, afef, snfcp)
    # ORL
    "sforl":                          "orl",                 # SFORL — ORL et chirurgie cervico-faciale
    # Gériatrie
    "sfgg":                           "geriatrie",           # SFGG — gériatrie et gérontologie
    # Gynécologie-obstétrique
    "cngof_recommandations":          "gynecologie",         # CNGOF — gynécologie obstétrique
    # Néphrologie
    "sfndt":                          "nephrologie",         # SFNDT — néphrologie et transplantation
    # Infectiologie & microbiologie
    "sfm_microbiologie":              "infectiologie",       # SFM — microbiologie / anti-infectieux
    # Hématologie
    "sfh":                            "hematologie",         # SFH — hématologie clinique
    # Ophtalmologie
    "sfo":                            "ophtalmologie",       # SFO — ophtalmologie
    # Chirurgie orthopédique
    "sofcot":                         "chirurgie-orthopedique",  # SOFCOT — orthopédie traumatologie
    # Chirurgie plastique
    "sofcpre_plastique":              "chirurgie-plastique", # SOFCPRE — chirurgie plastique reconstructrice
    # Oncologie soins de support
    "afsos":                          "oncologie",           # AFSOS — soins oncologiques de support
    # Médecine nucléaire
    "sfmn":                           "medecine-nucleaire",  # SFMN — médecine nucléaire
    # Médecine d'urgence
    "sfmu":                           "medecine-urgences",   # SFMU — médecine d'urgence
    # Biologie médicale (déjà: sfbc → biologiste)
    "sfbc":                           "biologiste",          # SFBC — biologie clinique
    # Infirmiers libéraux
    "sniil":                          "infirmiers",          # SNIIL — infirmiers libéraux
    # ── Sources réglementaires françaises — toutes spécialités ─────────────────
    # Ces sources sont collectées dans rss_collector.py et piste_routes.py.
    # specialty_hint="tous" : le LLM addendum de chaque spécialité filtre ce qui est pertinent.
    "legifrance_jorf":                "tous",        # JORF — lois, décrets, arrêtés santé
    "legifrance_jorf_remboursement":  "tous",        # JORF remboursement / nomenclature / conventions
    "piste_kali":                     "tous",        # Conventions collectives secteur santé (salariés cabinets, cliniques)
    "piste_legi":                     "tous",        # Code de la santé publique (modifications)
    "piste_circ":                     "tous",        # Circulaires ministérielles santé
    "ameli_medecin":                  "tous",        # ameli.fr — actualités médecins libéraux (convention, tarifs, outils)
    "cnom":                           "tous",        # CNOM — déontologie, exercice libéral, toutes spécialités
    "bo_social":                      "tous",        # BO Social — instructions DGS/DSS/DGOS, toutes spécialités
    "carmf":                          "tous",        # CARMF — retraite/cotisations médecins libéraux
    "carpimko":                       "tous",        # CARPIMKO — retraite auxiliaires médicaux (infirmiers, kiné, etc.)
    "has_rbp":                        "tous",        # HAS — Recommandations de bonne pratique
    "has_ct":                         "tous",        # HAS — Commission de Transparence (médicaments)
    "has_dm":                         "tous",        # HAS — Avis dispositifs médicaux
    "ansm_securite":                  "tous",        # ANSM — Informations de sécurité (global)
    "ansm_securite_med":              "tous",        # ANSM — Sécurité médicaments
    "ansm_securite_dm":               "tous",        # ANSM — Matériovigilance DM
    "ansm_actualites":                "tous",        # ANSM — Points d'information, communiqués
    "ansm_ruptures_med":              "tous",        # ANSM — Ruptures médicaments
    "ansm_ruptures_vaccins":          "tous",        # ANSM — Disponibilité vaccins
    "has_acces_precoces":             "tous",        # HAS — Accès précoce (ex-ATU) — cross-specialty
    "has_bo":                         "tous",        # HAS — Bulletin officiel (décisions formelles)
    "inca_recommandations":           "oncologie",   # INCa — Référentiels oncologie
    # ── Sources européennes (agences réglementaires EU) ───────────────────────
    "ema_news":           "tous",          # EMA — Alertes sécurité EU (retraits AMM, DHPCs) — cross-specialty
    "ema_guidelines":     "tous",          # EMA — Guidelines scientifiques EU — cross-specialty
    "ema_new_medicines":  "tous",          # EMA — Nouvelles AMM EU — cross-specialty
    "ecdc_risk":          "infectiologie", # ECDC — Risques épidémiques (maladies infectieuses)
    "ecdc_guidance":      "infectiologie", # ECDC — Recommandations prévention/contrôle infections
    "ecdc_cdtr":          "infectiologie", # ECDC — CDTR hebdo (surveillance maladies infectieuses)
    # ── Cardiologie ───────────────────────────────────────────────────────────
    "bmj_heart":                    "cardiologie",   # RSS Heart / BCS — cardiologie clinique (IF ~15)
    "circulation_aha":              "cardiologie",   # RSS Circulation (AHA, IF ~35)
    "jaha":                         "cardiologie",   # RSS JAHA (AHA open-access, IF ~5)
    "jacc_rss":                     "cardiologie",   # RSS JACC (Elsevier, IF ~24)
    "esc_guidelines":               "cardiologie",   # scraping ESC (déjà SOURCE_TO_TYPE)
    "pubmed_ehj_cardio":            "cardiologie",
    "pubmed_ejhf":                  "cardiologie",
    "pubmed_jacc_medical":          "cardiologie",
    "pubmed_jacc_hf":               "cardiologie",
    "pubmed_jacc_ep":               "cardiologie",
    "pubmed_heart_rhythm":          "cardiologie",
    "pubmed_europace":              "cardiologie",
    "pubmed_acvd":                  "cardiologie",
    "pubmed_esc_guidelines_cardio": "cardiologie",
    "pubmed_ehj_pharmacother":      "cardiologie",
    "pubmed_jacc_intv":             "cardiologie",
    "pubmed_eurointervention":      "cardiologie",
    "pubmed_circ_cardiovasc_intv":  "cardiologie",
    "pubmed_jacc_img":              "cardiologie",
    # ── Biologie médicale ─────────────────────────────────────────────────────
    "eflm_guidelines":              "biologiste",   # scraping EFLM (déjà SOURCE_TO_TYPE)
    "pubmed_clin_chem":             "biologiste",
    "pubmed_cclm":                  "biologiste",
    "pubmed_eflm_guidelines_cclm":  "biologiste",
    "pubmed_jcm":                   "biologiste",
    "pubmed_cmi":                   "biologiste",
    "pubmed_ann_clin_biochem":      "biologiste",
    "pubmed_ajcp":                  "biologiste",
    "pubmed_j_mol_diagn":           "biologiste",
    "pubmed_transfusion":           "biologiste",
    "pubmed_vox_sanguinis":         "biologiste",
    # ── Anesthésiologie-Réanimation ───────────────────────────────────────────
    "esicm":                        "anesthesiologie",  # RSS ESICM (déjà SOURCE_TO_TYPE)
    "esaic":                        "anesthesiologie",  # RSS ESAIC (déjà SOURCE_TO_TYPE)
    "sfar":                         "anesthesiologie",  # RSS SFAR (société savante FR)
    "pubmed_anesthesiology":        "anesthesiologie",
    "pubmed_bja":                   "anesthesiologie",
    "pubmed_anesth_analg":          "anesthesiologie",
    "pubmed_anaesthesia":           "anesthesiologie",
    "pubmed_eja":                   "anesthesiologie",
    "pubmed_accpm":                 "anesthesiologie",
    "pubmed_sfar_guidelines":       "anesthesiologie",
    "pubmed_reg_anesth":            "anesthesiologie",
    "pubmed_intensive_care_med":    "anesthesiologie",
    "pubmed_crit_care_med":         "anesthesiologie",
    "pubmed_crit_care":             "anesthesiologie",
    "pubmed_jcva":                  "anesthesiologie",
    "pubmed_acta_anaesthesiol_scand": "anesthesiologie",
    "pubmed_can_j_anaesth":         "anesthesiologie",
    "pubmed_pain_iasp":             "anesthesiologie",
    "pubmed_j_pain_res":            "anesthesiologie",
    "pubmed_paediatr_anaesth":      "anesthesiologie",
    # ── Dermatologie ──────────────────────────────────────────────────────────────
    "eadv":                         "dermatologie",   # RSS EADV (déjà SOURCE_TO_TYPE)
    "jaad_rss":                     "dermatologie",   # RSS JAAD (AAD/Elsevier, IF ~13)
    "bjd_rss":                      "dermatologie",   # RSS BJD (BAD/Wiley, IF ~11)
    "pubmed_jaad":                  "dermatologie",
    "pubmed_bjd":                   "dermatologie",
    "pubmed_jeadv":                 "dermatologie",
    "pubmed_eur_j_derm":            "dermatologie",
    "pubmed_jama_derm":             "dermatologie",
    "pubmed_acta_derm":             "dermatologie",
    "pubmed_dermatology_basel":     "dermatologie",
    "pubmed_clin_exp_derm":         "dermatologie",
    "pubmed_contact_derm":          "dermatologie",
    "pubmed_melanoma_res":          "dermatologie",
    "pubmed_jddg":                  "dermatologie",
    "pubmed_jid":                   "dermatologie",
    "pubmed_derm_therapy":          "dermatologie",
    "pubmed_j_derm_treat":          "dermatologie",
    "pubmed_pediatr_derm":          "dermatologie",
    "pubmed_int_j_derm":            "dermatologie",
    # ── endocrinologie ────────────────────────────────────────────────────────
    "lancet_diab_endo_rss":         "endocrinologie",  # RSS Lancet Diabetes & Endocrinology (IF ~44)
    "diabetes_care_rss":            "endocrinologie",  # RSS Diabetes Care (ADA, IF ~16)
    "pubmed_diabetes_care":         "endocrinologie",
    "pubmed_lancet_diab_endo":      "endocrinologie",
    "pubmed_diabetologia":          "endocrinologie",
    "pubmed_jcem":                  "endocrinologie",
    "pubmed_thyroid":               "endocrinologie",
    "pubmed_eur_j_endo":            "endocrinologie",
    "pubmed_diabetes_obes_metab":   "endocrinologie",
    "pubmed_osteoporos_int":        "endocrinologie",
    "pubmed_bone":                  "endocrinologie",
    "pubmed_clin_endo":             "endocrinologie",
    "pubmed_endocr_pract":          "endocrinologie",
    "pubmed_diabetes_res_clin":     "endocrinologie",
    "pubmed_j_endo_invest":         "endocrinologie",
    "pubmed_horm_metab_res":        "endocrinologie",
    "pubmed_endocrinology":         "endocrinologie",
    "pubmed_ann_endo":              "endocrinologie",
    # ── gastro-entérologie ────────────────────────────────────────────────────
    "lancet_gastro_hepatol":        "gastro-enterologie",  # RSS Lancet GH (IF ~35) — temps réel
    "bmj_gut":                      "gastro-enterologie",  # RSS Gut / BSG (IF ~24) — temps réel
    "pubmed_gut":                   "gastro-enterologie",
    "pubmed_gastroenterology":      "gastro-enterologie",
    "pubmed_ajg":                   "gastro-enterologie",
    "pubmed_hepatology":            "gastro-enterologie",
    "pubmed_j_hepatol":             "gastro-enterologie",
    "pubmed_lancet_gastro":         "gastro-enterologie",
    "pubmed_apt":                   "gastro-enterologie",
    "pubmed_cgh":                   "gastro-enterologie",
    "pubmed_jcc":                   "gastro-enterologie",
    "pubmed_endoscopy":             "gastro-enterologie",
    "pubmed_gie":                   "gastro-enterologie",
    "pubmed_jhep_rep":              "gastro-enterologie",
    "pubmed_liver_int":             "gastro-enterologie",
    "pubmed_dig_endosc":            "gastro-enterologie",
    "pubmed_ejgh":                  "gastro-enterologie",
    "pubmed_j_gastro_hepatol":      "gastro-enterologie",
    "snfge":                        "gastro-enterologie",  # RSS SNFGE (société savante FR)
    "afef":                         "gastro-enterologie",  # RSS AFEF hépatologie (sous-spé gastro)
    "snfcp":                        "gastro-enterologie",  # RSS SNFCP coloproctologie (sous-spé gastro)
    # ── gériatrie ─────────────────────────────────────────────────────────────
    "jags_rss":                     "geriatrie",   # RSS JAGS (AGS/Wiley, IF ~7)
    "pubmed_age_ageing":            "geriatrie",
    "pubmed_jags":                  "geriatrie",
    "pubmed_lancet_healthy_longev": "geriatrie",
    "pubmed_alzheimers_dement":     "geriatrie",
    "pubmed_j_gerontol_med":        "geriatrie",
    "pubmed_jamda":                 "geriatrie",
    "pubmed_eur_geriatr_med":       "geriatrie",
    "pubmed_int_j_geriatr_psychiatry": "geriatrie",
    "pubmed_j_alzheimers_dis":      "geriatrie",
    "pubmed_clin_interv_aging":     "geriatrie",
    "pubmed_bmc_geriatr":           "geriatrie",
    "pubmed_maturitas":             "geriatrie",
    "pubmed_j_nutr_health_aging":   "geriatrie",
    "pubmed_aging_clin_exp_res":    "geriatrie",
    "pubmed_geriatr_gerontol_int":  "geriatrie",
    "pubmed_gerontology":           "geriatrie",
    # ── Gynécologie ──────────────────────────────────────────────────────────
    "ajog_rss":                     "gynecologie",  # RSS AJOG (Elsevier, IF ~10)
    "pubmed_ajog":                  "gynecologie",
    "pubmed_obstet_gynecol":        "gynecologie",
    "pubmed_fertil_steril":         "gynecologie",
    "pubmed_bjog":                  "gynecologie",
    "pubmed_ultrasound_og":         "gynecologie",
    "pubmed_gynecol_oncol":         "gynecologie",
    "pubmed_hum_reprod":            "gynecologie",
    "pubmed_menopause_j":           "gynecologie",
    "pubmed_ijgc":                  "gynecologie",
    "pubmed_jmig":                  "gynecologie",
    "pubmed_ejogrb":                "gynecologie",
    "pubmed_aogs":                  "gynecologie",
    "pubmed_jgohr":                 "gynecologie",
    "pubmed_rbm_online":            "gynecologie",
    "pubmed_arch_gynecol":          "gynecologie",
    "pubmed_gynecol_endocrinol":    "gynecologie",
    # ── Hématologie ──────────────────────────────────────────────────────────
    "lancet_haematol":              "hematologie",   # RSS Lancet Haematology (IF ~27)
    "blood_rss":                    "hematologie",   # RSS Blood (ASH/Elsevier, IF ~25)
    "am_j_hematol":                 "hematologie",   # RSS Am J Hematology (Wiley, IF ~12)
    "leukemia_rss":                 "hematologie",   # RSS Leukemia (Nature, IF ~12)
    "pubmed_blood":                 "hematologie",
    "pubmed_leukemia":              "hematologie",
    "pubmed_haematologica":         "hematologie",
    "pubmed_am_j_hematol":          "hematologie",
    "pubmed_lancet_haematol":       "hematologie",
    "pubmed_br_j_haematol":         "hematologie",
    "pubmed_blood_adv":             "hematologie",
    "pubmed_j_hematol_oncol":       "hematologie",
    "pubmed_bone_marrow_transplant": "hematologie",
    "pubmed_thromb_haemost":        "hematologie",
    "pubmed_j_thromb_haemost":      "hematologie",
    "pubmed_ann_hematol":           "hematologie",
    "pubmed_leuk_lymphoma":         "hematologie",
    "pubmed_eur_j_haematol":        "hematologie",
    "pubmed_hematol_oncol":         "hematologie",
    "pubmed_clin_lymphoma_myeloma_leuk": "hematologie",
    # ── Infectiologie ─────────────────────────────────────────────────────────
    "lancet_infect_dis":            "infectiologie",  # RSS Lancet Infectious Diseases (IF ~40)
    "eid_cdc":                      "infectiologie",  # RSS Emerging Infect Diseases (CDC, IF ~12)
    "pubmed_cid":                   "infectiologie",
    "pubmed_lancet_infect_dis":     "infectiologie",
    "pubmed_j_infect_dis":          "infectiologie",
    "pubmed_aids_journal":          "infectiologie",
    "pubmed_aac":                   "infectiologie",
    "pubmed_jac":                   "infectiologie",
    "pubmed_emerg_infect_dis":      "infectiologie",
    "pubmed_ijaa":                  "infectiologie",
    "pubmed_j_infect":              "infectiologie",
    "pubmed_hiv_med":               "infectiologie",
    "pubmed_euro_surveill":         "infectiologie",
    "pubmed_mycoses":               "infectiologie",
    "pubmed_med_mal_infect":        "infectiologie",
    "pubmed_infection":             "infectiologie",
    "pubmed_eur_j_clin_microbiol":  "infectiologie",
    "pubmed_plos_ntd":              "infectiologie",
    # ── Infirmiers ────────────────────────────────────────────────────────────
    "pubmed_int_j_nurs_stud":       "infirmiers",
    "pubmed_j_adv_nurs":            "infirmiers",
    "pubmed_j_clin_nurs":           "infirmiers",
    "pubmed_nurse_educ_today":      "infirmiers",
    "pubmed_nurs_res":              "infirmiers",
    "pubmed_worldviews_ebn":        "infirmiers",
    "pubmed_int_wound_j":           "infirmiers",
    "pubmed_j_wound_care":          "infirmiers",
    "pubmed_wound_repair":          "infirmiers",
    "pubmed_pain_manag_nurs":       "infirmiers",
    "pubmed_appl_nurs_res":         "infirmiers",
    "pubmed_j_nurs_manag":          "infirmiers",
    "pubmed_eur_j_oncol_nurs":      "infirmiers",
    "pubmed_intensive_crit_care_nurs": "infirmiers",
    "pubmed_j_nurs_scholarsh":      "infirmiers",
    "pubmed_nurs_open":             "infirmiers",
    # ── Kinésithérapie ────────────────────────────────────────────────────────
    "pubmed_phys_ther":             "kinesitherapie",
    "pubmed_jospt":                 "kinesitherapie",
    "pubmed_j_physiother":          "kinesitherapie",
    "pubmed_br_j_sports_med_kine":  "kinesitherapie",
    "pubmed_clin_rehabil":          "kinesitherapie",
    "pubmed_arch_phys_med_rehabil": "kinesitherapie",
    "pubmed_disabil_rehabil":       "kinesitherapie",
    "pubmed_j_rehabil_med":         "kinesitherapie",
    "pubmed_bmc_musculoskelet":     "kinesitherapie",
    "pubmed_j_cardiopulm_rehabil":  "kinesitherapie",
    "pubmed_neurorehabil_neural_repair": "kinesitherapie",
    "pubmed_j_neuroeng_rehabil":    "kinesitherapie",
    "pubmed_ann_phys_rehabil_med":  "kinesitherapie",
    "pubmed_eur_j_phys_rehabil_med": "kinesitherapie",
    "pubmed_gait_posture":          "kinesitherapie",
    "pubmed_musculoskelet_sci_pract": "kinesitherapie",
    # ── Neurologie ────────────────────────────────────────────────────────────
    "lancet_neurology":               "neurologie",   # RSS Lancet Neurology (IF ~57)
    "bmj_jnnp":                       "neurologie",   # RSS JNNP / BMJ (IF ~9)
    "neurology_aan":                  "neurologie",   # RSS Neurology (AAN, IF ~9)
    "ann_neurol":                     "neurologie",   # RSS Annals of Neurology (Wiley, IF ~11)
    "stroke_aha":                     "neurologie",   # RSS Stroke (AHA/ASA, IF ~8) — neuro + neurochir
    "pubmed_neurology":               "neurologie",
    "pubmed_lancet_neurol":           "neurologie",
    "pubmed_brain":                   "neurologie",
    "pubmed_ann_neurol":              "neurologie",
    "pubmed_jnnp":                    "neurologie",
    "pubmed_eur_j_neurol":            "neurologie",
    "pubmed_j_neurol":                "neurologie",
    "pubmed_mov_disord":              "neurologie",
    "pubmed_epilepsia":               "neurologie",
    "pubmed_cephalalgia":             "neurologie",
    "pubmed_int_j_stroke":            "neurologie",
    "pubmed_cerebrovasc_dis":         "neurologie",
    "pubmed_parkinsonism_relat_disord":"neurologie",
    "pubmed_seizure":                 "neurologie",
    "pubmed_j_neurol_sci":            "neurologie",
    "pubmed_muscle_nerve":            "neurologie",
    # ── Neurochirurgie ────────────────────────────────────────────────────────
    "pubmed_j_neurosurg":             "neurochirurgie",
    "pubmed_neurosurgery":            "neurochirurgie",
    "pubmed_acta_neurochir":          "neurochirurgie",
    "pubmed_world_neurosurg":         "neurochirurgie",
    "pubmed_neuro_oncol":             "neurochirurgie",
    "pubmed_j_neurooncol":            "neurochirurgie",
    "pubmed_j_neurosurg_spine":       "neurochirurgie",
    "pubmed_eur_spine_j_nc":          "neurochirurgie",
    "pubmed_spine_j_nc":              "neurochirurgie",
    "pubmed_stroke":                  "neurochirurgie",
    "pubmed_neurocrit_care":          "neurochirurgie",
    "pubmed_j_neurosurg_pediatr":     "neurochirurgie",
    "pubmed_childs_nerv_syst":        "neurochirurgie",
    "pubmed_neurosurg_rev":           "neurochirurgie",
    "pubmed_clin_neurol_neurosurg":   "neurochirurgie",
    "pubmed_stereotact_funct_neurosurg": "neurochirurgie",
    "pubmed_oper_neurosurg":          "neurochirurgie",
    # ── Néphrologie ───────────────────────────────────────────────────────────
    "kidney_int_rss":                 "nephrologie",  # RSS Kidney International (ISN/Elsevier, IF ~14)
    "pubmed_jasn":                    "nephrologie",
    "pubmed_kidney_int":              "nephrologie",
    "pubmed_am_j_kidney_dis":         "nephrologie",
    "pubmed_nephrol_dial_transplant": "nephrologie",
    "pubmed_cjasn":                   "nephrologie",
    "pubmed_nephron":                 "nephrologie",
    "pubmed_nephrology_carlton":      "nephrologie",
    "pubmed_bmc_nephrol":             "nephrologie",
    "pubmed_perit_dial_int":          "nephrologie",
    "pubmed_hemodial_int":            "nephrologie",
    "pubmed_transplantation":         "nephrologie",
    "pubmed_am_j_transplant":         "nephrologie",
    "pubmed_transpl_int":             "nephrologie",
    "pubmed_j_nephrol":               "nephrologie",
    "pubmed_clin_nephrol":            "nephrologie",
    "pubmed_nephrol_ther":            "nephrologie",
    # ── Médecine d'urgences ───────────────────────────────────────────────────
    "ann_emerg_med_rss":              "medecine-urgences",  # RSS Ann Emerg Med (ACEP, IF ~9)
    "emj_rss":                        "medecine-urgences",  # RSS EMJ (RCEM/BMJ, IF ~4)
    "resuscitation_rss":              "medecine-urgences",  # RSS Resuscitation (ERC, IF ~6)
    "pubmed_ann_emerg_med":           "medecine-urgences",
    "pubmed_resuscitation":           "medecine-urgences",
    "pubmed_am_j_emerg_med":          "medecine-urgences",
    "pubmed_acad_emerg_med":          "medecine-urgences",
    "pubmed_injury":                  "medecine-urgences",
    "pubmed_emerg_med_j":             "medecine-urgences",
    "pubmed_j_trauma_acute_care_surg":"medecine-urgences",
    "pubmed_j_emerg_med":             "medecine-urgences",
    "pubmed_scand_j_trauma_resusc":   "medecine-urgences",
    "pubmed_eur_j_emerg_med":         "medecine-urgences",
    "pubmed_prehosp_emerg_care":      "medecine-urgences",
    "pubmed_emerg_med_australas":     "medecine-urgences",
    "pubmed_prehosp_disaster_med":    "medecine-urgences",
    "pubmed_clin_toxicol":            "medecine-urgences",
    "pubmed_j_crit_care_urg":         "medecine-urgences",
    "pubmed_west_j_emerg_med":        "medecine-urgences",
    # ── Médecine physique et de réadaptation ─────────────────────────────────
    "pubmed_pm_r":                    "medecine-physique",
    "pubmed_spinal_cord":             "medecine-physique",
    "pubmed_brain_inj":               "medecine-physique",
    "pubmed_top_stroke_rehabil":      "medecine-physique",
    "pubmed_j_head_trauma_rehabil":   "medecine-physique",
    "pubmed_int_j_rehabil_res":       "medecine-physique",
    "pubmed_neuropsychol_rehabil":    "medecine-physique",
    "pubmed_prosthet_orthot_int":     "medecine-physique",
    "pubmed_j_spinal_cord_med":       "medecine-physique",
    "pubmed_pain":                    "medecine-physique",
    "pubmed_eur_j_pain":              "medecine-physique",
    "pubmed_pain_med":                "medecine-physique",
    "pubmed_mult_scler":              "medecine-physique",
    "pubmed_mult_scler_relat_disord": "medecine-physique",
    "pubmed_toxins_mpr":              "medecine-physique",
    "pubmed_j_neurol_phys_ther":      "medecine-physique",
    "arch_pmr_rss":                   "medecine-physique",  # RSS Archives of PMR (ACRM/Elsevier)
    "pmrj_rss":                       "medecine-physique",  # RSS PM&R Journal (AAPM&R/Wiley)
    # ── Médecine interne ─────────────────────────────────────────────────────
    "ann_intern_med_rss":           "medecine-interne",  # RSS Ann Intern Med (ACP, IF ~51)
    "pubmed_ann_intern_med":        "medecine-interne",
    "pubmed_am_j_med":              "medecine-interne",
    "pubmed_medicine_baltimore":    "medecine-interne",
    "pubmed_bmc_med":               "medecine-interne",
    "pubmed_eur_j_clin_invest":     "medecine-interne",
    "pubmed_postgrad_med_j":        "medecine-interne",
    "pubmed_j_intern_med":          "medecine-interne",
    "pubmed_eur_j_intern_med":      "medecine-interne",
    "pubmed_mayo_clin_proc":        "medecine-interne",
    "pubmed_intern_med_j":          "medecine-interne",
    "pubmed_qjm":                   "medecine-interne",
    "pubmed_intern_emerg_med":      "medecine-interne",
    "pubmed_am_j_med_sci":          "medecine-interne",
    "pubmed_swiss_med_wkly":        "medecine-interne",
    "pubmed_j_investig_med":        "medecine-interne",
    "pubmed_rev_med_interne":       "medecine-interne",
    # ── Médecine générale ─────────────────────────────────────────────────────
    "cmaj_rss":                     "medecine-generale",  # RSS CMAJ (CMA, IF ~8)
    "bjgp_rss":                     "medecine-generale",  # RSS BJGP (RCGP, IF ~5)
    "pubmed_j_gen_intern_med":      "medecine-generale",
    "pubmed_j_hypertens":           "medecine-generale",
    "pubmed_prev_med":              "medecine-generale",
    "pubmed_int_j_clin_pract":      "medecine-generale",
    "pubmed_bjgp":                  "medecine-generale",
    "pubmed_am_j_prev_med":         "medecine-generale",
    "pubmed_cmaj":                  "medecine-generale",
    "pubmed_fam_pract":             "medecine-generale",
    "pubmed_bmc_fam_pract":         "medecine-generale",
    "pubmed_ann_fam_med":           "medecine-generale",
    "pubmed_prim_care_diabetes":    "medecine-generale",
    "pubmed_j_am_board_fam_med":    "medecine-generale",
    "pubmed_scand_j_prim_health":   "medecine-generale",
    "pubmed_bmc_prim_care":         "medecine-generale",
    "pubmed_npj_prim_care_respir":  "medecine-generale",
    "pubmed_eur_j_gen_pract":       "medecine-generale",
    # ── ORL ───────────────────────────────────────────────────────────────────
    "otohns_rss":                   "orl",  # RSS Otolaryngology HNS (AAO-HNS/SAGE, IF ~3)
    "laryngoscope_rss":             "orl",  # RSS Laryngoscope (ALA/Wiley, IF ~3)
    "head_neck_rss":                "orl",  # RSS Head & Neck (Wiley, IF ~3)
    "pubmed_otolaryngol_hns":       "orl",
    "pubmed_jama_otolaryngol":      "orl",
    "pubmed_laryngoscope":          "orl",
    "pubmed_head_neck":             "orl",
    "pubmed_oral_oncol":            "orl",
    "pubmed_eur_arch_orl":          "orl",
    "pubmed_otol_neurotol":         "orl",
    "pubmed_rhinology":             "orl",
    "pubmed_clin_otolaryngol":      "orl",
    "pubmed_int_forum_allergy_rhinol": "orl",
    "pubmed_thyroid":               "orl",
    "pubmed_acta_otolaryngol":      "orl",
    "pubmed_audiol_neurootol":      "orl",
    "pubmed_dysphagia":             "orl",
    "pubmed_j_voice":               "orl",
    "pubmed_epos_guidelines":       "orl",
    # ── Ophtalmologie ─────────────────────────────────────────────────────────
    "ophthalmology_aao":            "ophtalmologie",  # RSS Ophthalmology (AAO/Elsevier, IF ~14)
    "bjo_rss":                      "ophtalmologie",  # RSS BJO (BMJ, IF ~5)
    "pubmed_ophthalmology":         "ophtalmologie",
    "pubmed_jama_ophthalmol":       "ophtalmologie",
    "pubmed_br_j_ophthalmol":       "ophtalmologie",
    "pubmed_am_j_ophthalmol":       "ophtalmologie",
    "pubmed_retina":                "ophtalmologie",
    "pubmed_jcrs":                  "ophtalmologie",
    "pubmed_j_glaucoma":            "ophtalmologie",
    "pubmed_cornea":                "ophtalmologie",
    "pubmed_graefes_arch":          "ophtalmologie",
    "pubmed_acta_ophthalmol":       "ophtalmologie",
    "pubmed_eye":                   "ophtalmologie",
    "pubmed_surv_ophthalmol":       "ophtalmologie",
    "pubmed_iovs":                  "ophtalmologie",
    "pubmed_ocul_surf":             "ophtalmologie",
    "pubmed_eur_j_ophthalmol":      "ophtalmologie",
    "pubmed_prog_retin_eye_res":    "ophtalmologie",
    "egs_guidelines":               "ophtalmologie",   # EGS — glaucome (web scraping)
    "euretina_guidelines":          "ophtalmologie",   # EURETINA — rétine (web scraping)
    # ── Oncologie ─────────────────────────────────────────────────────────────
    "lancet_oncology":              "oncologie",   # RSS Lancet Oncology (IF ~51)
    "jco_rss":                      "oncologie",   # RSS JCO (ASCO, IF ~45)
    "ann_oncol_rss":                "oncologie",   # RSS Ann Oncol (ESMO, IF ~51)
    "pubmed_j_clin_oncol":          "oncologie",
    "pubmed_ann_oncol":             "oncologie",
    "pubmed_lancet_oncol":          "oncologie",
    "pubmed_eur_j_cancer":          "oncologie",
    "pubmed_clin_cancer_res":       "oncologie",
    "pubmed_br_j_cancer":           "oncologie",
    "pubmed_cancer_acs":            "oncologie",
    "pubmed_jnci":                  "oncologie",
    "pubmed_int_j_radiat_oncol":    "oncologie",
    "pubmed_radiother_oncol":       "oncologie",
    "pubmed_support_care_cancer":   "oncologie",
    "pubmed_cancer_treat_rev":      "oncologie",
    "pubmed_oncologist":            "oncologie",
    "pubmed_esmo_open":             "oncologie",
    "pubmed_cancer_med":            "oncologie",
    "pubmed_oncotarget":            "oncologie",
    "esmo":                         "oncologie",   # RSS ESMO guidelines
    # ── Pharmacien ────────────────────────────────────────────────────────────
    "br_j_clin_pharm_rss":           "pharmacien",  # RSS BJCP (BPS/Wiley, IF ~4)
    "ann_pharmacother_rss":          "pharmacien",  # RSS Ann Pharmacotherapy (SAGE, IF ~4)
    "pubmed_clin_pharmacol_ther":    "pharmacien",
    "pubmed_ann_pharmacother":       "pharmacien",
    "pubmed_br_j_clin_pharmacol":    "pharmacien",
    "pubmed_pharmacotherapy":        "pharmacien",
    "pubmed_drug_safety":            "pharmacien",
    "pubmed_pharmacoepidemiol_drug_saf": "pharmacien",
    "pubmed_am_j_health_syst_pharm": "pharmacien",
    "pubmed_eur_j_hosp_pharm":       "pharmacien",
    "pubmed_int_j_clin_pharm":       "pharmacien",
    "pubmed_drugs":                  "pharmacien",
    "pubmed_clin_pharmacokinet":     "pharmacien",
    "pubmed_biodrugs":               "pharmacien",
    "pubmed_eur_j_clin_pharmacol":   "pharmacien",
    "pubmed_ann_pharm_fr":           "pharmacien",
    "pubmed_ther_adv_drug_saf":      "pharmacien",
    "pubmed_j_clin_pharm_ther":      "pharmacien",
    "eahp_statements":               "pharmacien",  # EAHP Good Practice Statements (web scraping)
    "fspf":                          "pharmacien",  # FSPF — Fédération syndicale pharmaciens France
    # ── Pneumologie ───────────────────────────────────────────────────────────
    "lancet_respir_med":             "pneumologie",  # RSS Lancet Respiratory Medicine (IF ~38)
    "bmj_thorax":                    "pneumologie",  # RSS Thorax / BTS (IF ~10)
    "chest_rss":                     "pneumologie",  # RSS Chest (ACCP, IF ~9)
    "pubmed_eur_respir_j":           "pneumologie",
    "pubmed_ajrccm":                 "pneumologie",
    "pubmed_lancet_respir":          "pneumologie",
    "pubmed_eur_respir_rev":         "pneumologie",
    "pubmed_ann_am_thorac_soc":      "pneumologie",
    "pubmed_jaci":                   "pneumologie",
    "pubmed_pulmonology":            "pneumologie",
    "pubmed_respirology":            "pneumologie",
    "pubmed_respir_med":             "pneumologie",
    "pubmed_sleep":                  "pneumologie",
    "pubmed_j_sleep_res":            "pneumologie",
    "pubmed_rev_mal_respir":         "pneumologie",
    "ers":                           "pneumologie",   # RSS ERS (déjà SOURCE_TO_TYPE → recommandation)
    "splf":                          "pneumologie",   # SPLF (déjà SOURCE_TO_TYPE → recommandation)
    # ── Psychiatrie ───────────────────────────────────────────────────────────
    "lancet_psychiatry":             "psychiatrie",  # RSS Lancet Psychiatry (IF ~65)
    "pubmed_am_j_psychiatry":        "psychiatrie",
    "pubmed_jama_psychiatry":        "psychiatrie",
    "pubmed_lancet_psychiatry":      "psychiatrie",
    "pubmed_world_psychiatry":       "psychiatrie",
    "pubmed_br_j_psychiatry":        "psychiatrie",
    "pubmed_acta_psychiatr_scand":   "psychiatrie",
    "pubmed_schizophr_bull":         "psychiatrie",
    "pubmed_bipolar_disord":         "psychiatrie",
    "pubmed_neuropsychopharmacol":   "psychiatrie",
    "pubmed_j_clin_psychiatry":      "psychiatrie",
    "pubmed_depress_anxiety":        "psychiatrie",
    "pubmed_int_j_neuropsychopharmacol": "psychiatrie",
    "pubmed_encephale":              "psychiatrie",
    "epa_psychiatrie":               "psychiatrie",   # RSS EPA (European Psychiatric Association)
    "sfpsychiatrie":                 "psychiatrie",   # RSS SPF
    # ── Radiologie ────────────────────────────────────────────────────────────
    "eur_radiol_rss":                "radiologie",  # RSS European Radiology (Springer, IF ~7)
    "pubmed_radiology":              "radiologie",
    "pubmed_eur_radiology":          "radiologie",
    "pubmed_radiol_interv":          "radiologie",
    "pubmed_jvir":                   "radiologie",
    "pubmed_cvir":                   "radiologie",
    "pubmed_ajnr":                   "radiologie",
    "pubmed_ajr":                    "radiologie",
    "pubmed_radiographics":          "radiologie",
    "pubmed_ejnmmi":                 "radiologie",
    "pubmed_j_nucl_med":             "radiologie",
    "pubmed_insights_imaging":       "radiologie",
    "pubmed_eur_j_radiol":           "radiologie",
    "esr_radiologie":                "radiologie",   # RSS ESR (European Society of Radiology)
    "sfr_radiologie":                "radiologie",   # SFR (Société Française de Radiologie)
    # ── Rhumatologie ──────────────────────────────────────────────────────────
    "lancet_rheumatol":              "rhumatologie",  # RSS Lancet Rheumatology (IF ~25)
    "bmj_ard":                       "rhumatologie",  # RSS ARD / EULAR-BMJ (IF ~27)
    "arthritis_rheumatol_rss":       "rhumatologie",  # RSS Arthritis & Rheumatology (ACR/Wiley, IF ~14)
    "pubmed_ard":                    "rhumatologie",
    "pubmed_arthritis_rheumatol":    "rhumatologie",
    "pubmed_rheumatology_oxford":    "rhumatologie",
    "pubmed_j_autoimmun":            "rhumatologie",
    "pubmed_osteoarthritis_cartilage": "rhumatologie",
    "pubmed_arthritis_res_ther":     "rhumatologie",
    "pubmed_j_rheumatol":            "rhumatologie",
    "pubmed_rmd_open":               "rhumatologie",
    "pubmed_semin_arthritis_rheum":  "rhumatologie",
    "pubmed_lupus":                  "rhumatologie",
    "pubmed_clin_rheumatol":         "rhumatologie",
    "pubmed_rev_rhum":               "rhumatologie",
    "ard_eular":                     "rhumatologie",   # RSS ARD/EULAR
    "eular_recommendations":         "rhumatologie",   # web scraping EULAR guidelines
    "sfrhumato":                     "rhumatologie",   # RSS SFR
    # ── Sage-femme ────────────────────────────────────────────────────────────
    "pubmed_midwifery":              "sage-femme",
    "pubmed_birth":                  "sage-femme",
    "pubmed_women_birth":            "sage-femme",
    "pubmed_j_midwifery":            "sage-femme",
    "pubmed_prenat_diagn":           "sage-femme",
    "pubmed_j_matern_fetal":         "sage-femme",
    "pubmed_breastfeed_med":         "sage-femme",
    "pubmed_j_hum_lact":             "sage-femme",
    "pubmed_arch_womens_ment_health": "sage-femme",
    "pubmed_matern_child_nutr":      "sage-femme",
    "pubmed_int_breastfeed_j":       "sage-femme",
    "cnsf":                          "sage-femme",    # CNSF (Collège National des Sages-Femmes)
    "bjog":                          "sage-femme",    # BJOG RSS (RCOG — obstétrique/maïeutique)
    "eshre_guidelines":              "sage-femme",    # ESHRE guidelines (procréation, grossesse)
    # ── Urologie ──────────────────────────────────────────────────────────────
    "pubmed_eur_urol":               "urologie",
    "pubmed_eur_urol_oncol":         "urologie",
    "pubmed_j_urol":                 "urologie",
    "pubmed_prostate_cancer":        "urologie",
    "pubmed_bjui":                   "urologie",
    "pubmed_eur_urol_focus":         "urologie",
    "pubmed_world_j_urol":           "urologie",
    "pubmed_j_endourol":             "urologie",
    "pubmed_neurourol_urodyn":       "urologie",
    "pubmed_urology":                "urologie",
    "pubmed_int_j_urol":             "urologie",
    "pubmed_prog_urol":              "urologie",
    "eau_guidelines":                "urologie",     # web scraping EAU guidelines
    "afu":                           "urologie",     # RSS AFU (déjà SOURCE_TO_TYPE → recommandation)
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
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


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
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


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
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


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

_SPECIALTY_ADDENDUM_PEDIATRIQUE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CHIRURGIE PÉDIATRIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : chirurgien pédiatrique (CHU / centre hospitalier régional, France / Europe), \
maîtrisant chirurgie ouverte ET techniques laparoscopiques/thoracoscopiques pédiatriques \
(appendicite, fundoplicature Nissen, pyloromyotomie, pull-through Hirschsprung, \
PIRS hernie inguinale, résection CPAM thoracoscopique, nephrectomie/pyéloplastie). \
Spécialiste de l'ensemble chirurgie néonatale (atrésie œsophagienne, HDC, gastroschisis), \
chirurgie digestive, urologie pédiatrique, oncologie chirurgicale pédiatrique. \
Référentiels actuels : IPEG guidelines 2022-2024, APSA clinical practice guidelines, \
EUPSA/ESPES consensus, EAU Pediatric Urology guidelines 2023, SIOP WT 2016 \
(Wilms), SFCP recommandations françaises, HAS. \
Essais pivots récents de référence : ped-STAR (antibiothérapie vs appendicectomie enfant), \
IPEG RCT fundoplicature, études EUPSA atrésie biliaire (Kasai), \
COG vs SIOP Wilms (chimiothérapie préopératoire ou non).

CRITÈRE DE PERTINENCE PÉDIATRIQUE :
"Ce résultat va-t-il modifier une indication opératoire, le choix d'une voie d'abord \
(ouverte vs laparoscopique), une stratégie de prise en charge périopératoire, \
ou une recommandation de société savante dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires sans gain de précision, \
population pédiatrique d'un seul pays non représentatif de la pratique française \
(cohorte monocentrique asiatique sans équivalent anatomique/technique), \
sous-groupe non pré-spécifié sur moins de 30 patients.

FILTRES SPÉCIFIQUES :
→ Retenir en priorité : RCTs comparant voie ouverte vs laparoscopique en chirurgie \
pédiatrique, méta-analyses sur complications malformations congénitales, guidelines \
IPEG/EUPSA/EAU Pediatric, alertes sécurité sur dispositifs médicaux pédiatriques, \
études multicentriques sur oncologie chirurgicale pédiatrique (Wilms, neuroblastome). \
→ Rejeter : séries rétrospectives monocentriques < 50 patients sans comparateur, \
études de techniques expérimentales sans cohorte prospective, études purement \
anesthésiques (relevant de l'anesthésiste pédiatrique et non du chirurgien).

TERMINOLOGIE — employer sans guillemets ni définition :
AO (atrésie œsophagienne), type C (atrésie + fistule trachéo-œsophagienne distale), \
long gap AO (diastasis > 3 cm, Foker ou Kimura), HDC (hernie diaphragmatique congénitale), \
ECMO (extracorporeal membrane oxygenation — pré-réparation HDC), O/E LHR (observed/expected \
lung-head ratio — pronostic HDC), NEC (entérocolite nécrosante), GEA (gastro-entérite aiguë), \
CPAM (congenital pulmonary airway malformation — ancien MAKV), séquestration broncho-pulmonaire, \
pectus excavatum (PE), indice de Haller (IH — PE sévère si > 3,25), Nuss (barres pectorales), \
Ravitch (sternochondroplastie), SHP (sténose hypertrophique du pylore), \
Fredet-Ramstedt (pyloromyotomie), pyloromyotomie laparoscopique vs ouverte, \
IIA (invagination intestinale aiguë), désinvagination pneumatique/hydrostatique, \
appendicite aiguë non compliquée (AANC) / compliquée (plastron, abcès, péritonite), \
ped-STAR (essai antibiothérapie appendicite), PIRS (percutaneous internal ring suturing — \
hernie inguinale laparoscopique), orchidopexie trans-scrotale, \
Fowler-Stephens (orchidopexie 2 temps testicule intra-abdominal), \
SJPU (sténose jonction pyélo-urétérale), pyéloplastie d'Andersen-Hynes (ouverte ou robot), \
RVU (reflux vésico-urétéral), grades I-V (classification internationale), \
STING/HIT (injection sous-urétérale endoscopique anti-RVU), Cohen (réimplantation urétérale), \
VUP (valves de l'urètre postérieur), hypospadias TIP (Snodgrass), tubularisation Mathieu, \
SIOP (International Society of Paediatric Oncology — protocole Wilms chimiothérapie \
néo-adjuvante), COG (Children's Oncology Group — chirurgie d'emblée Wilms), \
TW (tumeur de Wilms) stade I-V, ERACS (enhanced recovery after children's surgery — \
réhabilitation améliorée chirurgie pédiatrique).

EXEMPLES DE RÉDACTION (style JPS / EJPS / PSI — format cible) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai clinique laparoscopie vs chirurgie ouverte :
  titre_court : "Appendicite AANC pédiatrique : cœlio vs ouverte — RCT 2 ans"
  resume : "RCT multicentrique (N=520, appendicite non compliquée, 5-17 ans, suivi 24 mois) : \
taux de succès sans réintervention 89,4 % (laparoscopie) vs 86,1 % (ouverte) — \
non-infériorité confirmée (marge 10 %, p=0,021). Durée d'hospitalisation : −0,8 j \
(laparoscopie). Abcès de paroi : 1,2 % vs 4,7 % (p=0,003). \
Pas de différence sur récidive ou occlusion postopératoire à 2 ans."
  impact_pratique : "En pratique : laparoscopie confirme sa supériorité sur les complications \
de paroi — à privilégier quand disponible, particulièrement chez l'adolescente (risque \
d'erreur diagnostique avec pathologie ovarienne)."

Guideline IPEG :
  titre_court : "IPEG 2023 : hernie inguinale pédiatrique — PIRS recommandée bilatéralité"
  resume : "IPEG Clinical Practice Guideline (2023) : hernie inguinale pédiatrique. \
Ligature haute du sac en chirurgie ouverte reste le standard (recommandation forte, \
preuves modérées). PIRS (percutaneous internal ring suturing) recommandée pour les \
hernies bilatérales et les récidives (recommandation forte, preuves modérées). \
Chirurgie contralat. de principe non recommandée chez > 6 mois (risque hernie \
métachrone < 10 % — EAU Pediatric)."
  impact_pratique : "À retenir : PIRS bilatérale en une seule anesthésie — à proposer \
dès que hernie inguinale bilatérale suspectée chez < 2 ans."

Alerte sécurité dispositif pédiatrique :
  titre_court : "ANSM : retrait élastiques hémostase néonatale — lot xxxx"
  resume : "ANSM (décision xx 2026) : retrait de lots d'élastiques hémostatiques \
pédiatriques (marque X, lot xxxx) après 3 cas de nécrose digitale chez des \
nouveau-nés en matériovigilance. Dispositifs utilisés en chirurgie néonatale \
d'atrésie et en urétroplastie. Mesure conservatoire immédiate."
  impact_pratique : "En pratique : vérifier les stocks et écarter les lots concernés — \
utiliser un équivalent homologué ou une ligature en attendant la résolution."
"""

_SPECIALTY_ADDENDUM_PEDIATRIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — PÉDIATRIE GÉNÉRALE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : pédiatre généraliste (libéral ou hospitalier, France / Europe), \
prenant en charge des enfants de 0 à 18 ans. Compétences : pathologies courantes \
(infections ORL, respiratoires, digestives, urinaires), croissance et développement, \
nutrition pédiatrique (AME, diversification alimentaire), vaccins (calendrier DGS), \
urgences pédiatriques de premier recours (fièvre, convulsions, déshydratation), \
pathologies chroniques communes (asthme, TDAH, obésité, épilepsie). \
Référentiels actuels : recommandations SFP, AAP (Red Book, Clinical Practice \
Guidelines publiées dans Pediatrics), ESPGHAN, ESPID, HCSP, HAS, calendrier \
vaccinal DGS. \
Essais pivots récents de référence : SEREN (bronchiolite haut débit), \
NIRSEVIMAB MELODY/HARMONIE (nirsévimab RSV), LEAP (arachide et prévention \
allergie), SNIFFLE (LAIV grippe), PREVENTIA (prévention asthme), \
INTERGROWTH-21st (courbes de croissance).

CRITÈRE DE PERTINENCE PÉDIATRIE :
"Ce résultat va-t-il modifier une décision lors d'une consultation ou d'un \
appel pour un enfant malade dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une pratique \
déjà établie sans gain de précision clinique, population non représentative de \
la pratique FR/EU (ex. pays à faibles revenus sans extrapolation possible), \
sous-spécialité nécessitant un recours spécialisé systématique (cardiopathies \
congénitales complexes, oncologie pédiatrique, chirurgie, génétique) sauf si \
l'article donne un critère de recours direct pour le pédiatre de premier recours. \
Rejeter aussi : pure épidémiologie sans conséquence pratique, études de cohorte \
monocentriques N<200 sur pathologies communes, bibliométrie, opinion.

FILTRES SPÉCIFIQUES PÉDIATRIE :
→ RETENIR en priorité :
  • RCTs ou méta-analyses sur infections pédiatriques courantes (ORL, urinaires, respiratoires, \
méningites) modifiant le choix de l'antibiotique, la durée ou les critères d'hospitalisation.
  • Guidelines AAP, SFP, ESPID, ESPGHAN, HCSP/DGS sur vaccination, dépistage, nutrition, \
pathologies chroniques (asthme, TDAH, épilepsie, obésité).
  • Études sur la bronchiolite, la fièvre sans foyer du nourrisson, la déshydratation aiguë — \
population de premier recours, décision pratique claire.
  • Alertes pharmacovigilance ou matériovigilance concernant des médicaments pédiatriques courants \
(antibiotiques, antipyrétiques, antiépileptiques, corticoïdes inhalés).
  • Résultats sur la prévention (nirsévimab RSV, LAIV, méningocoque B, HPV, introduction \
précoce des allergènes) avec impact sur le calendrier vaccinal ou les pratiques de consultation.
→ REJETER sans hésiter :
  • Sous-spécialités à recours systématiquement spécialisé sans critère d'adressage pour le pédiatre \
de premier recours : cardiopathies congénitales complexes (HTAP sévère, canal artériel chirurgical), \
oncologie pédiatrique (sauf critères d'alerte et d'adressage), génétique (sauf conseil en consultation).
  • Études portant exclusivement sur la réanimation pédiatrique (PICU) sans implication sur \
la prise en charge de premier recours ou le critère d'admission.
  • Études purement néonatales en maternité de niveau III (prématurité extrême < 28 SA, \
ECMO, NO) sans lien avec le suivi ambulatoire du prématuré modéré.
  • Résultats de pays à faibles revenus (sub-sahariens, Asie du Sud-Est) sans possibilité \
d'extrapolation à la pratique française (épidémiologie, ressources, antibiogramme différents).
  • Études comportementales/psychosociales sans endpoint clinique mesurable en consultation \
(études d'attitude, de perception, de bien-être général sans outcome santé).
  • Séries rétrospectives monocentriques N < 200 sur pathologies communes.

TERMINOLOGIE — employer sans guillemets ni définition :
RSV / VRS, bronchiolite, nirsévimab, palivizumab, haut débit nasal (HFT), \
LAIV (vaccin vivant atténué intranasal grippe), ROR, DTPCaHibHepB (hexavalent), \
méningocoque B/ACWY, pneumocoque 13/15/20-valent, HPV, calendrier vaccinal, \
zone orange/rouge (score de gravité), score de Westley (laryngite), \
score PEWS / PEVS / PIM, CRP/PCT/NFS, ECBU / nitrites / leucocytes, \
courbe de poids/taille/PC (z-score, percentile), IMC (corpulence), \
diversification alimentaire (DA), allergie aux protéines de lait de vache (APLV), \
IgE spécifiques / Prick-test, SCORAD (eczéma), ACQ / ACT (asthme), \
TDAH (score SDQ / SNAP-IV), TSA (score M-CHAT), convulsion fébrile simple/complexe, \
statut épileptique, déshydratation (score Gorelick), SRO (soluté de réhydratation), \
prématurité (AG, PC à la naissance), courbes INTERGROWTH-21st.

EXEMPLES DE RÉDACTION (style Pediatrics AAP / Archives of Disease in Childhood) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


RCT vaccin / prévention :
  titre_court : "Nirsévimab : protection RSV nourrisson 77 % — MELODY N=1 490"
  resume : "MELODY (RCT, N=1 490, nourrissons <1 an, 8 pays) : nirsévimab 50/100 mg \
vs placebo. Hospitalisation pour BARI à RSV : 0,6 % vs 4,9 % (réduction relative \
77 % ; IC95% 60–87 %, p<0,001). Durée médiane de protection évaluée à 5 mois. \
Profil de sécurité identique au placebo. Homologation EMA jan. 2023 + \
recommandation HCSP oct. 2023 pour tous les nourrissons en première saison \
épidémique."
  impact_pratique : "À retenir : nirsévimab recommandé pour tous les nourrissons \
nés <6 mois avant le début de l'épidémie RSV et ceux en 2ème saison à risque — \
prescrire en octobre-novembre selon le calendrier épidémique régional."

Guideline AAP / mise à jour recommandation :
  titre_court : "AAP 2024 — fièvre sans foyer <3 mois : stratification risque low/high"
  resume : "Mise à jour des Clinical Practice Guidelines AAP sur la prise en charge \
de la fièvre sans foyer chez le nourrisson <3 mois (Pediatrics 2024). Stratification \
en trois groupes selon CRP, NFS et marqueurs infectieux : low risk (CRP<2 mg/L, \
NFS normale) → surveillance ambulatoire sans antibiothérapie ni PL ; intermediate \
risk → PL facultative selon contexte ; high risk → hospitalisation et antibiothérapie \
empirique systématique. Seuil de fièvre abaissé à 38°C dès 8 jours de vie."
  impact_pratique : "En pratique : appliquer la stratification AAP 2024 avec \
CRP+NFS pour les nourrissons <3 mois fébriles — évite la PL systématique en \
low-risk et réduit les hospitalisations inutiles."

Étude de cohorte / épidémio avec impact direct :
  titre_court : "LEAP : introduction arachide dès 4 mois divise l'allergie par 5 — N=640"
  resume : "LEAP (RCT, N=640, nourrissons 4-11 mois à risque allergie arachide, \
NEJM 2015 ; confirmation LEAP-On 2016) : consommation précoce d'arachide dès \
4 mois vs éviction jusqu'à 60 mois. Allergie à 60 mois : 1,9 % (introduction) \
vs 13,7 % (éviction) — RR 0,14 (p<0,001). Bénéfice maintenu à 72 mois \
(follow-up LEAP-Trio). Sécurité : 0 anaphylaxie fatale dans le groupe introduction."
  impact_pratique : "En pratique : introduire l'arachide dès 4-6 mois chez les \
nourrissons à risque (eczéma modéré-sévère ou allergie à l'œuf) — l'éviction \
préventive augmente le risque d'allergie et n'est plus recommandée."
"""

_SPECIALTY_ADDENDUM_ANESTHESIOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — ANESTHÉSIOLOGIE-RÉANIMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : médecin anesthésiste-réanimateur (MAR) exerçant en CHU ou \
clinique privée, France / Europe. Double compétence : anesthésie péri-opératoire \
(programmée et urgente) ET réanimation/soins intensifs (chirurgicale ou médicale). \
Maîtrise : anesthésie générale (TIVA, volatils), anesthésie locorégionale (ALR — \
rachianesthésie, péridurale, blocs nerveux périphériques écho-guidés), gestion des \
voies aériennes (IOT, vidéolaryngoscope, intubation difficile), monitoring \
hémodynamique (ETO, PiCCO, VPP), prise en charge du choc, du SDRA, de la \
défaillance multiviscérale, analgésie multimodale et protocoles ERAS. \
Référentiels actuels : SFAR recommandations 2022-2024, ESAIC guidelines, \
ESICM guidelines, Surviving Sepsis Campaign 2021, ARDS Network, protocoles \
ERAS Society (colorectal, orthopédique, urologique). \
Essais pivots récents de référence : PROSEVA (décubitus ventral SDRA), \
ANDROMEDA-SHOCK (microcirculation choc septique), SMART/SALT-ED (cristalloïdes), \
PADIS (analgosédation ICU), POPULAR-ANAESTHESIA (TIVA vs volatils \
en chirurgie carcinologique), REGAIN (rachianesthésie vs AG pour fracture col fémur).

CRITÈRE DE PERTINENCE ANESTHÉSIOLOGIE :
"Ce résultat va-t-il modifier un choix anesthésique, un protocole de réanimation \
ou une stratégie péri-opératoire dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une pratique \
déjà établie sans gain de précision clinique, études sur des populations de soins \
intensifs médicaux sans transposabilité à la réanimation chirurgicale, études \
pharmacologiques de phase 1-2 sans implication clinique directe, recherche \
fondamentale sur mécanismes (inflammation, protéomique, biomarqueurs) sans \
recommandation opérationnelle.

FILTRES SPÉCIFIQUES ANESTHÉSIOLOGIE :
→ RETENIR en priorité :
  • RCTs ou méta-analyses modifiant le choix ou la séquence d'induction (agents, doses, \
techniques ALR vs AG, vidéolaryngoscope systématique ou non).
  • Études sur l'analgésie péri-opératoire multimodale (blocs écho-guidés TAP/ESP/serratus, \
analgésie préemptive, opioïde-sparing) modifiant un protocole ERAS.
  • Guidelines SFAR, ESAIC, ESICM sur voies aériennes, décurarisation, sécurité \
anesthésique, monitorage neuromusculaire — directement opposables en France.
  • Alertes pharmacovigilance sur agents anesthésiques (curares, hypnotiques, analgésiques \
opioïdes, curares inverseurs) ou dispositifs médicaux de bloc opératoire (respirateurs, \
moniteurs BIS, pompes TIVA, sondes IOT à ballonnet défectueux).
  • Résultats en réanimation modifiant la stratégie de ventilation protectrice, \
d'analgosédation (RASS cible, dexmedetomidine, kétamine), de décision de décubitus ventral, \
ou de vasopresseur de choix (noradrénaline, vasopressine, angiotensine II).
  • Études sur la récupération améliorée après chirurgie (ERAS) avec endpoints \
durée d'hospitalisation, complications majeures, douleur J1, consommation d'opioïdes.
  • Études sur la prévention de la douleur chronique post-opératoire (DCPO) : \
kétamine, dexmédétomidine, analgésie préemptive, blocs nerveux prolongés.
  • Recommandations sur le jeûne préopératoire (liquides clairs, délais) et la \
prévention du réveil peropératoire (monitoring BIS/EEG, protocoles TIVA).
→ REJETER sans hésiter :
  • Études de réanimation médicale pure (sepsis médical, pneumonie communautaire, \
insuffisance cardiaque décompensée) sans aucune transposabilité péri-opératoire ni \
technique anesthésique — conserver si le résultat modifie un protocole de prise en \
charge que le MAR applique aussi en réanimation chirurgicale.
  • Études sur l'IA en anesthésie (algorithmes de prédiction, CDSS) sans RCT de \
validation clinique avec endpoint patient.
  • Articles sur l'organisation des soins, les ratios infirmiers en réanimation, \
la gestion des lits — sans implication sur la pratique clinique du MAR.
  • Études monocentriques sur techniques ALR rares (< 50 patients) sans comparateur actif.
  • Pharmaco-économie et coûts hospitaliers sans impact sur la décision clinique.

TERMINOLOGIE — employer sans guillemets ni définition :
IOT (intubation orotrachéale), VL (vidéolaryngoscope — McGrath, C-MAC, GlideScope), \
masque laryngé (ML), DSI (delayed sequence intubation), CICO (cannot intubate cannot \
oxygenate), RSI (rapid sequence induction), crush induction, TIVA (total intravenous \
anaesthesia — propofol + rémifentanil TCI), anesthésie balancée (propofol + volatil), \
MAC (minimum alveolar concentration), BIS (index bispectral — profondeur anesthésie), \
TOF (train-of-four — monitorage curarisation), NMB (neuromuscular blockade), \
sugammadex (antagoniste sélectif stéroïdiens), néostigmine, curarisation résiduelle, \
T4/T1 ratio, ALR (anesthésie locorégionale), rachianesthésie, APD (analgésie \
péri-durale), TAP block (transversus abdominis plane), ESP block (erector spinae plane), \
serratus block, PECS I/II, bloc interscalénique, bloc fémoral, bloc poplité, \
écho-guidage (guidage échographique ALR), ERAS (enhanced recovery \
after surgery), préhabilitation, analgésie multimodale, opioïde-sparing, \
PCA (patient-controlled analgesia), score NRS/EVA (douleur), CPOT (douleur ICU), \
NAD/norépinéphrine (noradrénaline), vasopressine, phényléphrine, \
VPP (variation de pression pulsée), ITV (intégrale temps-vitesse), \
DC (débit cardiaque), ETO (échocardiographie transœsophagienne), PiCCO, \
SDRA (syndrome de détresse respiratoire aiguë), P/F (PaO2/FiO2), VT (volume courant), \
PPlat (pression plateau), PEEP (positive end-expiratory pressure), \
décubitus ventral (DV — PROSEVA), pronation, ECMO-VV, ECMO-VA, \
SOFA score, qSOFA, sepsis-3, choc septique (NAD ≥ 0,1 µg/kg/min + lactate ≥ 2 mmol/L), \
RASS (Richmond Agitation Sedation Scale), CAM-ICU (delirium), \
dexmedetomidine, kétamine, midazolam, propofol ICU, \
ABCDEF bundle (analgésie/sédation/delirium/mobilisation/famille).

SOURCES CONFIGURÉES POUR CETTE SPÉCIALITÉ (à titre d'information) :
PubMed (17 sources) : Anesthesiology (ASA, IF ~9), Br J Anaesth (BJA, IF ~9), \
Anesth Analg (IARS, IF ~5), Anaesthesia (AAGBI, IF ~10), Eur J Anaesthesiol \
(ESAIC, IF ~6), Anaesth Crit Care Pain Med (SFAR/ACCPM), SFAR Guidelines \
(RFE canal dédié), Reg Anesth Pain Med (ASRA, IF ~8), Intensive Care Med \
(ESICM, IF ~30), Crit Care Med (SCCM, IF ~8), Crit Care (BioMed Central, IF ~15), \
J Cardiothorac Vasc Anesth (SOCCA, IF ~5), Acta Anaesthesiol Scand (SSAI, IF ~4), \
Can J Anaesth (CAS, IF ~4), PAIN (IASP, IF ~7), J Pain Res (open-access), \
Paediatr Anaesth (APAGBI, IF ~3).
RSS (2 sources) : ESICM (esicm.org), ESAIC (esaic.org).
Note : les 5 journaux flagship (Anesthesiology, BJA, Anesth&Analg, Anaesthesia, EJA) \
utilisent _PT_OR_TITLE pour capter les articles récents non encore tagués NLM.

EXEMPLES DE RÉDACTION (style Anesthesiology / BJA / Intensive Care Medicine / \
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\

Annales Françaises d'Anesthésie et de Réanimation) :

RCT technique anesthésique :
  titre_court : "TIVA vs volatils en chirurgie colorectale carcinologique : POPULAR"
  resume : "POPULAR-ANAESTHESIA (RCT, N=2 132, chirurgie colorectale pour cancer, \
suivi 1 an) : survie sans récidive à 1 an 81,7 % (TIVA-propofol) vs 82,2 % \
(sévoflurane) — HR 1,02 (IC95% 0,84–1,23 ; p=0,85). Aucune supériorité de la TIVA \
sur la survie carcinologique. Mortalité à 30 j et complications majeures : équivalents \
entre groupes. L'hypothèse immunoprotectrice du propofol n'est pas confirmée."
  impact_pratique : "À retenir : le choix TIVA vs volatils peut reposer sur des \
critères pratiques (NVPO, environnement, coût) — la survie carcinologique n'est \
plus un argument différenciant."

Guideline voies aériennes :
  titre_court : "SFAR 2022 — vidéolaryngoscope en 1re ligne pour IOT programmée"
  resume : "Recommandations SFAR sur la prise en charge des voies aériennes \
difficiles (2022) : vidéolaryngoscope recommandé comme technique de 1re intention \
pour toute intubation programmée (recommandation forte, grade 1+). \
Algorithme CICO actualisé : oxygénation d'apnée systématique + kit de \
cricothyroïdotomie immédiatement disponible. Déclaration obligatoire de tout \
échec d'intubation difficile imprévue au registre NAP."
  impact_pratique : "En pratique : équiper chaque salle d'opération d'un VL et \
former l'ensemble du personnel — le laryngoscope direct en 1re intention n'est \
plus la norme SFAR."

Alerte pharmacovigilance :
  titre_court : "ANSM : contamination lot rocuronium 50 mg — retrait immédiat"
  resume : "ANSM (décision xx 2026) : retrait du lot xxxx de rocuronium bromure \
50 mg/5 mL (Fresenius Kabi) après détection de particules visibles en contrôle \
qualité. Environ 4 200 flacons distribués en France depuis janvier 2026. \
Mesure conservatoire immédiate — aucun incident clinique déclaré à ce stade."
  impact_pratique : "En pratique : identifier et mettre en quarantaine les flacons \
du lot concerné dans les armoires de bloc et de réanimation — utiliser les stocks \
non impactés ou basculer sur vécuronium."

Résultat réanimation :
  titre_court : "Décubitus ventral précoce hors SDRA : PROACT-K négatif"
  resume : "PROACT-K (RCT, N=400, choc septique sans SDRA, P/F > 200) : mortalité \
à J28 26,4 % (DV précoce 8h) vs 24,8 % (décubitus dorsal) — différence non \
significative (OR 1,09 ; IC95% 0,72–1,64 ; p=0,68). Complications de positionnement \
plus fréquentes dans le groupe DV (désextubation accidentelle 4,2 % vs 0,8 %). \
Le bénéfice du DV reste réservé au SDRA sévère (P/F < 150)."
  impact_pratique : "À retenir : ne pas élargir le DV au choc septique sans SDRA \
sévère — le rapport bénéfice/risque ne le justifie pas hors critères PROSEVA."
"""

_SPECIALTY_ADDENDUM_BIOLOGISTE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — BIOLOGIE MÉDICALE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : biologiste médical (PH hospitalier ou directeur de laboratoire \
libéral), France / Europe. Responsable de la validation analytique et \
interprétative des résultats, du management qualité (accréditation COFRAC \
ISO 15189), et du conseil aux cliniciens sur le choix et l'interprétation des \
examens. Compétences couvrant l'ensemble des disciplines du laboratoire : \
biochimie clinique (enzymes, protéines, marqueurs cardiaques, rénaux, hépatiques, \
tumoraux), hématologie (NFS-formule, coagulation, exploration des hémostases), \
microbiologie (bactériologie, virologie, mycologie, parasitologie — cultures, \
antibiogrammes, CMI, biologie moléculaire PCR/NGS), immunologie (auto-anticorps, \
allergologie, immunophénotypage), génétique moléculaire (NGS panels oncogénétique, \
FISH, CGH-array, PCR quantitative), et transfusion/immuno-hématologie (groupage, \
RAI, produits sanguins labiles). \
Référentiels actuels : GBEA (guide de bonne exécution des analyses de biologie \
médicale, art. L6211), COFRAC SH REF 02 (ISO 15189 accréditation), \
recommandations SFBMédecine, SFBC (biochimie), SFM (Société Française de Microbiologie), \
EFLM (European Federation of Clinical Chemistry and Laboratory Medicine), \
ESCMID guidelines antibiogramme/résistances, EUCAST breakpoints (actualisés \
annuellement), CLSI standards, ANSM décisions réactifs/DM.

CRITÈRE DE PERTINENCE BIOLOGIE MÉDICALE :
"Ce résultat va-t-il modifier un seuil décisionnel, un algorithme diagnostique, \
une technique d'analyse, une interprétation de résultat ou une procédure de \
laboratoire dans les 1-3 ans ?" \
Rejeter même une étude bien conduite si : pas de seuil clinique opérationnel \
défini, biomarqueur encore en phase de découverte sans validation analytique \
(coefficient de variation, stabilité préanalytique), étude sur \
équipements non disponibles en France, ou résultats confirmant ce qui est déjà \
intégré dans la pratique quotidienne sans gain de précision.

FILTRES SPÉCIFIQUES BIOLOGIE MÉDICALE :
→ RETENIR en priorité :
  • Nouveaux seuils décisionnels validés cliniquement : hs-troponine (algorithmes \
0h/1h/2h ESC), D-dimères âge-ajustés (âge × 10 µg/L > 50 ans — YEARS/ADJUST), \
NT-proBNP âge-ajusté (seuil IC), HbA1c (cibles ADA/EASD révisées), \
ferritine (nouvelles valeurs de référence femme), clairance cystatine C vs créatinine.
  • Alertes résistances microbiologiques émergentes : nouvelles carbapénémases \
(NDM, OXA-48, KPC), BLSE épidémiques, Candida auris résistant, BMR/BHR nouvelles \
espèces — avec impact direct sur les antibiogrammes à réaliser et les antibiotiques \
à tester.
  • Recommandations analytiques EFLM/EUCAST/CLSI : pré-analytique (délais \
centrifugation, tubes, conservation), valeurs de référence nouvelles populations, \
performances analytiques (imprecision goals, bias allowable), contrôle qualité \
interne et externe (EEQ/PT).
  • Nouvelles techniques entrant en routine : PCR multiplexe (panels respiratoires, \
sepsis, digestif), séquençage métagénomique clinique, NGS en hémato-oncologie \
(panels somatiques), biopsie liquide (ctDNA), MALDI-TOF nouvelles identifications, \
spectrométrie de masse couplée (LC-MS/MS stéroïdes, immunosuppresseurs, drogues).
  • Alertes ANSM/EMA sur réactifs, calibrateurs, contrôles ou dispositifs médicaux \
de diagnostic in vitro (DMDIV) : retraits de lot, performances insuffisantes, \
interférences médicamenteuses ou analytiques identifiées.
  • Interférences analytiques majeures : hémoglobines anormales sur HbA1c, \
biotine sur immunodosages (surdosage > 5 mg/j), macro-prolactinémie, \
facteur rhumatoïde sur immunodosages, hémolyse/ictère/lipémie (HIL) sur automates courants.
→ REJETER sans hésiter :
  • Études cliniques évaluant l'efficacité d'un traitement sans implication sur \
l'interprétation biologique ou le choix d'examens.
  • Biomarqueurs exploratoires de phase de découverte (protéomique, métabolomique) \
sans seuil analytique ni validation multicentrique.
  • Études in vitro sur modèles cellulaires ou animaux sans résultats analytiques \
transposables au laboratoire clinique.
  • Techniques disponibles uniquement dans quelques laboratoires de recherche \
sans industrialisation en vue (< 3 ans).
  • Épidémiologie descriptive des résistances sans recommandation sur les \
antibiogrammes à réaliser ou les antibiotiques à tester.

TERMINOLOGIE — employer sans guillemets ni définition :
NFS-formule (numération formule sanguine), réticulocytes, VGM, CCMH, \
TP (taux de prothrombine), TCA (temps de céphaline activée), fibrinogène, \
D-dimères, INR, antithrombine, Facteur V Leiden, APCR, \
hs-troponine I/T (haute sensibilité — algorithmes 0h/1h ESC), \
NT-proBNP/BNP (insuffisance cardiaque), CRP us (ultrasensible), \
PCT (procalcitonine — seuil sepsis 0,5 µg/L), lactate, \
créatinine (Jaffé vs enzymatique), DFGe CKD-EPI 2021 (cystatine C), \
microalbuminurie (ratio albumine/créatinine), HbA1c (NGSP/IFCC), \
bilan hépatique (ASAT/ALAT/GGT/PAL/bilirubine totale et conjuguée), \
albumine, protéine C réactive, orosomucoïde, ferritine, transferrine, \
TSH (3e génération), T4L, T3L, anti-TPO, anti-thyroglobuline, \
PSA total/libre, AFP, ACE/CEA, CA 19-9, CA 125, CA 15-3, \
β-hCG (total — UE), LDH, CK, CK-MB, myoglobine, \
VPN/VPP (valeur prédictive négative/positive), ROC/AUC (aire sous la courbe), \
sensibilité analytique/clinique, spécificité analytique/clinique, \
CMI (concentration minimale inhibitrice), CMB, antibiogramme standardisé EUCAST, \
BLSE (β-lactamase à spectre élargi), SARM (Staph aureus résistant méticilline), \
ERV (entérocoque résistant vancomycine), EPC (entérobactérie productrice de carbapénémase), \
NDM/OXA-48/KPC (carbapénémases), Candida auris, \
MALDI-TOF (identification microbienne par spectrométrie de masse), \
PCR quantitative (qPCR), PCR multiplexe (panel respiratoire/digestif/méningite), \
NGS (next-generation sequencing — panel somatique/germinal), \
FISH (fluorescence in situ hybridization), CGH-array, \
biopsie liquide (ctDNA/ADN tumoral circulant), \
LC-MS/MS (chromatographie liquide couplée spectrométrie de masse — stéroïdes, IS, \
thérapeutiques), immunodosage (ELISA, ECLIA, CLIA, CLEIA), \
interférence HIL (hémolyse/ictère/lipémie), interférence biotine, \
macro-enzyme (macroprolactine, macro-CK), \
COFRAC (accréditation ISO 15189), GBEA, EEQ (évaluation externe qualité), \
CV (coefficient de variation — imprecision), biais analytique (bias), \
valeur de référence, delta-check (variation entre deux résultats successifs), \
valeur critique (panic value — délai notification obligatoire), \
pré-analytique (délai centrifugation, tube sec/EDTA/citrate, conservation).

EXEMPLES DE RÉDACTION (style Clinical Chemistry / CCLM / \
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\

Annales de Biologie Clinique / Journal de Biologie Médicale) :

Nouveau seuil décisionnel validé :
  titre_court : "D-dimères âge-ajustés : réduction des imageries inutiles sans perte de sécurité"
  resume : "L'étude ADJUST-PE (cohorte prospective, N=3 346, suspicion d'EP) valide \
le seuil D-dimères âge-ajusté (âge × 10 µg/L chez les > 50 ans) : sensibilité \
maintenue à 97,0 % (IC95% 93,1–98,9), spécificité améliorée de 34 % à 46 % \
(p < 0,001). Adoption de ce seuil éviterait 30 % des angioscanners thoraciques \
chez les patients âgés sans augmenter le taux de diagnostics manqués (0/331 \
patients faux-négatifs à 3 mois — 0 EP fatale)."
  impact_pratique : "En pratique : adopter le seuil âge × 10 µg/L pour les \
patients > 50 ans dans l'algorithme diagnostique EP — valider avec le service \
d'urgence local et mettre à jour la fiche interprétative du compte-rendu."

Alerte résistance microbiologique :
  titre_court : "Candida auris résistant : première détection en France — protocole laboratoire"
  resume : "Signal ECDC (avril 2026) : 12 cas de Candida auris résistant aux \
échinocandines confirmés dans 4 établissements français (CHU Paris, Lyon, Bordeaux, \
Montpellier). Identification MALDI-TOF insuffisante (confusion C. haemulonii) — \
séquençage ITS obligatoire pour confirmation. CMI micafungine ≥ 4 mg/L, \
CMI amphotéricine B ≥ 2 mg/L dans tous les cas. Mortalité à J30 : 58 %."
  impact_pratique : "En pratique : tout isolat de Candida non-albicans atypique \
doit être soumis à séquençage ITS et test de résistance aux échinocandines — \
ne pas se fier au MALDI-TOF seul pour cette espèce."

Recommandation analytique EFLM :
  titre_court : "EFLM 2025 : nouvelles spécifications analytiques pour la hs-troponine"
  resume : "Recommandation EFLM/IFCC 2025 sur les spécifications de performance \
analytique (APS) pour la hs-troponine cardiaque T et I : CV < 10 % au 99e \
percentile, biais analytique < 10 % vs méthode de référence LC-MS/MS, \
commutabilité des matériaux de contrôle qualité requise. Application obligatoire \
pour maintenir l'accréditation COFRAC ISO 15189 dans les laboratoires déclarant \
utiliser les algorithmes 0h/1h ESC (N = ~280 laboratoires en France)."
  impact_pratique : "En pratique : vérifier que la méthode hs-troponine de votre \
automate respecte ces APS — si non, adapter le seuil 99e percentile en conséquence \
et informer les cliniciens de l'impact sur l'interprétation."

Nouvelle technique entrant en routine :
  titre_court : "Métagénomique clinique (mNGS) vs culture : performances dans le sepsis"
  resume : "Étude prospective multicentrique (N=521, sepsis documenté ou probable, \
5 CHU européens) : sensibilité mNGS plasma 73 % vs 51 % pour les hémocultures \
(p < 0,001), délai de rendu 18 h vs 48-72 h. Détection de résistances (gènes \
blaCTX-M, mecA, vanA) concordante à 94 % avec antibiogramme phénotypique. \
Coût par examen : 380 € vs 45 € hémoculture — rapport coût/efficacité positif \
uniquement pour les sepsis graves en réanimation (SOFA ≥ 8)."
  impact_pratique : "En pratique : réserver le mNGS aux sepsis graves en réanimation \
chez les patients déjà traités ou immunodéprimés, en complément et non en \
remplacement des hémocultures."
"""

_SPECIALTY_ADDENDUM_CARDIOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CARDIOLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : cardiologue hospitalier (CHU/CH) ou libéral, France / Europe. \
Exercice polyvalent ou spécialisé en : insuffisance cardiaque (IC — HFrEF, \
HFmrEF, HFpEF), cardiologie interventionnelle (SCA, PCI, coronarographie), \
rythmologie (FA, arythmies ventriculaires, ablation RF/cryo/PFA, PM/DAI/CRT), \
prévention cardiovasculaire et lipidologie, échocardiographie et imagerie \
cardiaque (IRM cardiaque, scanner coronarien), cardiopathies valvulaires \
(suivi médical, TAVI côté cardiologue), cardiologie aiguë (SCA, OAP, choc \
cardiogénique, tamponnade), cardiomyopathies (CMH, ARVC, amylose cardiaque), \
hypertension artérielle pulmonaire (HTAP), cardio-oncologie. \
Référentiels actuels : ESC guidelines 2022-2024 (IC, FA, SCA, valvulopathies, \
HTA, dyslipidémies, MTEV, HTAP, cardiomyopathies), recommandations HAS, \
EHRA guidelines (arythmies, FA), HRS/ACC/AHA guidelines. \
Essais pivots de référence : EMPEROR-Reduced/Preserved/Pooled et DAPA-HF \
(iSGLT2 en IC), DELIVER (dapagliflozine HFmrEF/HFpEF), STRONG-HF \
(intensification post-hospitalisation IC), EAST-AFNET 4 (contrôle précoce \
rythme FA), CABANA (ablation FA vs médical), CASTLE-AF (ablation FA + FEVG \
altérée), ORION-10/VICTORION-2P (inclisiran LDL), CLEAR (bempédoïque acide), \
REDUCE-IT (icosapentaénoïque EPA), COMPASS (rivaroxaban prévention CV), \
ARISTOTLE/RELY/ROCKET-AF (NACO en FA), AFFIRM-AHF (fer IV IC décompensée).

CRITÈRE DE PERTINENCE CARDIOLOGIE :
"Ce résultat va-t-il modifier un traitement médicamenteux, une indication de \
procédure interventionnelle (PCI, ablation, implantation PM/DAI/CRT), un protocole \
de surveillance ou une stratégie de prévention cardiovasculaire dans les 1-3 ans ?"
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une classe déjà \
établie sans nouvelle indication ni gain clinique, études en chirurgie cardiaque \
(TAVI côté chirurgien, pontages — relèvent de chirurgie-cardiaque), recherche \
fondamentale sur mécanismes (signalisation, remodelage cellulaire), études \
uniquement épidémiologiques sans implication thérapeutique.

FILTRES SPÉCIFIQUES CARDIOLOGIE :
→ RETENIR en priorité :
  • RCTs/méta-analyses modifiant le traitement de l'IC : nouvelles indications \
iSGLT2 (IC à FEVG préservée, MRC), vericiguat, omecamtiv mecarbil, ARNi \
(sacubitril/valsartan) nouvelles populations, mavacamten (CMH obstructive).
  • Nouvelles recommandations ESC/EHRA/HRS directement opposables en France : \
IC, FA (score ABC-bleeding, ablation en 1re ligne), SCA (stratégie PCI précoce), \
valvulopathies, cardiomyopathies, HTAP.
  • Résultats ablation FA : technologies nouvelles (ablation par impulsion de champ \
PFA — PULSED AF, ADVENT), comparaisons ablation vs médical dans sous-groupes \
(FEVG altérée, FA persistante longue durée), rechutes et re-procédures.
  • Nouvelles indications PM/DAI/CRT, DAI sous-cutané (S-ICD), PM sans sonde \
(Micra), resynchronisation cardiaque — résultats à long terme, sélection patient.
  • Prévention CV : nouvelles classes ou nouvelles indications — PCSK9i \
(évolocumab, alirocumab) prévention primaire, inclisiran (ARNsi bimenstriel), \
acide bempédoïque, iSGLT2 prévention CV sans IC, GLP-1 (sémaglutide SELECT).
  • Alertes pharmacovigilance cardiovasculaires : dronédarone (hépatotoxicité), \
ivabradine (interactions), NACO (interactions médicamenteuses majeures), \
statines (rhabdomyolyse, interactions CYP3A4), digoxine (fenêtre thérapeutique).
  • Cardio-oncologie : myocardite sous inhibiteurs de checkpoint (ICI), \
cardiotoxicité anthracyclines/trastuzumab (protocoles surveillance FEVG), \
prise en charge fibrillation auriculaire sous thérapies ciblées.
  • Biomarqueurs décisionnels : BNP/NT-proBNP guided therapy (stratégie de titration \
IC), galectine-3, ST2 soluble (pronostic IC), troponine ultrasensible (SCA).
→ REJETER sans hésiter :
  • Chirurgie cardiaque : pontages (CABG), TAVI côté chirurgien, chirurgie \
valvulaire — relèvent de la spécialité chirurgie-cardiaque.
  • Réanimation cardiaque générale (arrêt cardiaque, ACR extra-hospitalier) \
sans interface directe avec la prise en charge cardiologique médicale.
  • Biologie fondamentale : mécanismes cellulaires cardiaques, physiopathologie \
moléculaire IC, signalisation β-adrénergique — sans recommandation opérationnelle.
  • Phase 1-2 sans endpoint clinique patient ou population non-transposable.
  • Épidémiologie descriptive incidence/prévalence sans implication thérapeutique.

TERMINOLOGIE — employer sans guillemets ni définition :
IC (insuffisance cardiaque), HFrEF (FEVG ≤ 40 %), HFmrEF (FEVG 41-49 %), \
HFpEF (FEVG ≥ 50 %), FEVG (fraction d'éjection ventriculaire gauche), \
remodelage ventriculaire inverse, VO₂max (test d'effort cardiopulmonaire), \
BNP/NT-proBNP (peptides natriurétiques), IRM cardiaque (CMR — \
strain longitudinal global, fibrose myocardique, T1/T2 mapping), \
SCA (syndrome coronarien aigu), NSTEMI, STEMI, angor stable, \
PCI (angioplastie coronarienne percutanée), stent actif (DES), \
FFR (réserve fractionnelle de flux), iFR, OCT (tomographie cohérence optique), \
IVUS (échographie intracoronaire), score SYNTAX, score GRACE, score TIMI, \
FA (fibrillation auriculaire) — paroxystique/persistante/permanente, \
flutter auriculaire, ESV/TVNS (extrasystoles ventriculaires/tachycardie \
ventriculaire non soutenue), TV soutenue, FV (fibrillation ventriculaire), \
score CHA₂DS₂-VASc, score HAS-BLED, score ABC-bleeding, \
ablation par radiofréquence (RF), cryoablation, ablation par impulsion de \
champ (PFA — pulsed-field ablation), isolation des veines pulmonaires (IVP), \
PM (pacemaker), PM sans sonde (Micra), DAI (défibrillateur automatique \
implantable), S-ICD (DAI sous-cutané), CRT-P/CRT-D (resynchronisation), \
IEC (inhibiteur de l'enzyme de conversion), ARA2 (sartans), \
ARNi (sacubitril/valsartan — Entresto), iSGLT2 (empagliflozine/dapagliflozine), \
ivabradine, vericiguat, mavacamten (inhibiteur myosine CMH), \
statines, PCSK9i (évolocumab — Repatha, alirocumab — Praluent), \
inclisiran (ARNsi anti-PCSK9 — bimenstriel), acide bempédoïque, \
NACO/AOD (apixaban/rivaroxaban/dabigatran/edoxaban), héparine (HNF/HBPM), \
HTAP (hypertension artérielle pulmonaire), mPAP, RVP (résistances \
vasculaires pulmonaires), antagonistes des récepteurs à l'endothéline \
(macitentan, ambrisentan), iPDE5 (tadalafil, sildénafil), \
prostacyclines (époprosténol, iloprost, tréprostinil), \
sélexipag (agoniste sélectif du récepteur IP — prostacycline receptor agonist), \
riociguat (sGC stimulateur), \
CMH (cardiomyopathie hypertrophique — obstructive CMHO ou non-obstructive), \
mavacamten (inhibiteur myosine cardiaque — CMHO avec gradient ≥ 30 mmHg), \
amylose cardiaque TTR (tafamidis — Vyndaqel), ARVC (dysplasie arythmogène \
ventriculaire droite), myocardite ICI (inhibiteurs de checkpoint immunitaire — \
anti-PD1/PDL1/CTLA4), cardiotoxicité anthracyclines/trastuzumab/imatinib, \
TAVI (remplacement valvulaire aortique transcathéter — côté cardiologue Heart Team), \
échocardiographie transthoracique (ETT), ETO (transœsophagienne), \
stress écho, échographie de contraste, GLS (global longitudinal strain).

EXEMPLES DE RÉDACTION (style European Heart Journal / JACC / \
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\

Archives de Maladies du Cœur et des Vaisseaux / La Revue du Praticien Cardiologie) :

RCT nouvelle indication IC :
  titre_court : "Dapagliflozine dans l'IC à FEVG préservée : DELIVER confirme le bénéfice"
  resume : "La dapagliflozine réduit de 18 % le risque d'aggravation de l'IC ou de \
décès CV dans l'HFpEF/HFmrEF (HR 0,82 ; IC95% 0,73–0,92 ; p<0,001) — DELIVER, \
RCT multicentrique, N=6 263, FEVG >40 %, NT-proBNP élevé, suivi médian 2,3 ans. \
Le bénéfice est homogène quelle que soit la FEVG (40–60 % et >60 %) ; les \
hospitalisations pour IC sont réduites de 23 % ; la mortalité CV seule n'atteint \
pas la significativité (HR 0,88 ; IC95% 0,74–1,05). Pas d'excès d'amputation ni de DKA."
  points_cles : [
    "Réduction de 18 % du critère composite aggravation IC/décès CV (HR 0,82 ; p<0,001) — premier iSGLT2 à démontrer ce bénéfice dans l'HFpEF",
    "Hospitalisations pour IC réduites de 23 % (HR 0,77 ; IC95% 0,67–0,89)",
    "Bénéfice homogène quelle que soit la FEVG (sous-groupes 40–60 % et >60 %)",
    "Pas de signal de sécurité : amputation, fracture, DKA comparables au placebo",
    "Efficacité indépendante du statut diabétique (interaction non significative)"
  ]
  texte_long : "DELIVER s'inscrit dans la continuité d'EMPEROR-Preserved (empagliflozine, \
HR 0,79 ; p<0,001) et constitue la deuxième démonstration de classe confirmant le \
bénéfice des iSGLT2 dans l'HFpEF. La population incluse est plus large qu'EMPEROR-Preserved \
(FEVG >40 % sans borne supérieure), ce qui renforce la généralisabilité. Les résultats \
secondaires — réduction du score de symptômes KCCQ (+2,5 points vs placebo, p<0,001) et \
de la mortalité toutes causes (HR 0,90 ; IC95% 0,78–1,03, NS) — indiquent un bénéfice \
fonctionnel cohérent sans atteindre la significativité sur la mortalité isolée. Limite \
principale : l'étude n'était pas dimensionnée pour la mortalité CV seule. En pratique \
française, la dapagliflozine dispose d'une AMM dans l'IC indépendamment de la FEVG \
depuis 2023 ; DELIVER fournit la base de données pour le remboursement dans l'HFpEF."
  impact_pratique : "En pratique : la dapagliflozine est désormais indiquée dans \
l'IC à FEVG préservée — à initier dès le diagnostic, indépendamment du diabète, \
en complément du traitement diurétique."

Guideline ESC — nouvelle recommandation FA :
  titre_court : "ESC 2023 FA : ablation en 1re ligne et nouveau score ABC-bleeding"
  resume : "Recommandations ESC 2023 sur la fibrillation auriculaire : ablation \
par cathéter recommandée en 1re ligne pour le contrôle du rythme chez les patients \
symptomatiques (recommandation de classe I, niveau B), avant toute tentative par \
antiarythmiques (renforcement vs 2020). Adoption du score ABC-bleeding (Age, \
Biomarqueurs — NT-proBNP/hs-cTnT, Clinique — AVC/saignement antérieur) pour \
stratifier le risque hémorragique sous NACO, en remplacement du score HAS-BLED \
(meilleure discrimination AUC 0,72 vs 0,61 dans la cohorte de validation)."
  impact_pratique : "En pratique : proposer l'ablation en 1re intention aux patients \
FA symptomatiques éligibles — ne plus attendre l'échec des antiarythmiques pour \
référer en rythmologie."

Alerte pharmacovigilance :
  titre_court : "Dronédarone : hépatotoxicité grave — nouvelles contre-indications ANSM"
  resume : "ANSM/EMA (2026) : révision du RCP dronédarone (Multaq) après analyse \
de 47 cas d'hépatotoxicité grave en France (dont 8 insuffisances hépatiques \
fulminantes, 2 décès). Surveillance mensuelle des transaminases recommandée les \
6 premiers mois (vs trimestrielle précédemment). Nouvelles CI absolues : \
ALAT > 3N avant initiation, antécédent d'hépatite médicamenteuse, association \
aux antifongiques azolés systémiques."
  impact_pratique : "En pratique : bilan hépatique mensuel les 6 premiers mois \
sous dronédarone, puis trimestriel — arrêt immédiat si ALAT > 3N ou symptômes \
hépatiques (asthénie inexpliquée, ictère)."

Cardio-oncologie :
  titre_court : "Myocardite sous anti-PD1 : protocole de surveillance et prise en charge"
  resume : "Étude de cohorte internationale (N=964 myocardites ICI, 20 centres, \
2015-2025) : incidence 0,09 % de toutes les expositions aux ICI, mortalité \
hospitalière 25,7 % — la plus haute de toutes les toxicités ICI. Anti-PD1 seuls \
(46 %), anti-PD1 + anti-CTLA4 (35 %). Délai médian d'apparition : 34 jours \
(IQR 21-75). Facteurs prédictifs de gravité : troponine > 1,5 µg/L, BAV du 3e \
degré, FEVG < 50 % à l'admission."
  impact_pratique : "En pratique : toute suspicion de myocardite sous ICI impose \
un ECG, une troponine hs et une IRM cardiaque en urgence — arrêt immédiat de \
l'immunothérapie et corticothérapie IV sans attendre la confirmation IRM."
"""

_SPECIALTY_ADDENDUM_THORACIQUE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CHIRURGIE THORACIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : chirurgien thoracique (CHU / clinique, France / Europe), \
maîtrisant résection pulmonaire (VATS/RATS lobectomie, segmentectomie, \
pneumonectomie), chirurgie de l'œsophage (MIE, Ivor Lewis, McKeown), \
chirurgie médiastinale (thymomectomie, tumeurs médiastinales), \
gestion des épanchements pleuraux (drainage, pleurodèse, PleurX), \
chirurgie des pneumothorax (bullectomie VATS), chirurgie trachéo-bronchique. \
Référentiels actuels : ESTS guidelines, IASLC staging 8e éd. (2017), \
ESMO guidelines cancer poumon résécable 2023-2024, HAS, INCa, \
recommandations SFCTCV. \
Essais pivots récents de référence : CALGB 140503 (segmentectomie vs \
lobectomie NSCLC ≤ 2 cm, NEJM 2023), JCOG 0802 (idem population japonaise, \
Lancet 2022), CheckMate 816 (nivolumab néoadjuvant NSCLC résécable IB-IIIA, \
NEJM 2022), ADAURA (osimertinib adjuvant EGFR+ stade IB-IIIA, NEJM 2023), \
ALINA (alectinib adjuvant ALK+ stade IB-IIIA, NEJM 2023), \
IMpower010 (atézolizumab adjuvant PD-L1 ≥ 1%, Lancet 2021), \
CROSS (radio-chimio néoadjuvante cancer œsophage, NEJM 2012 — standard actuel), \
FLOT4 (FLOT péri-opératoire adénocarcinome EGJ/estomac — impacte chirurgie \
œsophago-gastrique, Lancet 2019), NELSON (LDCT dépistage — réduction mortalité \
24 % hommes, NEJM 2020).

CRITÈRE DE PERTINENCE THORACIQUE :
"Ce résultat va-t-il modifier une indication opératoire, l'étendue d'une \
résection, la stratégie péri-opératoire (immuno/chimio néo-adjuvante/adjuvante), \
ou la technique chirurgicale dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : oncologie médicale pure sans composante \
chirurgicale, pneumologie médicale pure sans impact sur résécabilité ou technique, \
radiothérapie exclusive sans comparaison avec la résection, \
sous-groupe non pré-spécifié sur petits effectifs.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Étendue de la résection pulmonaire : segmentectomie vs lobectomie selon taille \
  et stade TNM (stade IA ≤ 2 cm : données CALGB 140503, JCOG 0802), \
  wedge resection (résection cunéiforme) vs segmentectomie anatomique
→ Voie d'abord : VATS vs RATS vs thoracotomie — morbi-mortalité, \
  LOS (durée de séjour), résultats oncologiques (marges R0, curage ganglionnaire)
→ Immuno/chimio-thérapie péri-opératoire : impact sur timing chirurgical, \
  taux de down-staging (pCR, MPR), complications post-op, résultats OS/DFS
→ Biomarqueurs guidant la décision chirurgicale : EGFR, ALK, ROS1, KRAS G12C, \
  MET exon 14 (adjuvant/néoadjuvant), PD-L1 TPS (immunothérapie néoadjuvante)
→ Staging médiastinal N2/N3 : EBUS vs médiastinoscopie, valeur prédictive \
  résécabilité cN2, prise en charge chirurgicale des N2 inattendus
→ Cancer de l'œsophage : MIE vs chirurgie ouverte (morbi-mortalité, \
  résultats oncologiques), gestion de l'anastomose œsophago-gastrique \
  (fistule anastomotique), protocoles CROSS + chirurgie vs FLOT + chirurgie
→ Mésothéliome pleural malin (MPM) : pleurectomie-décortication (P/D) \
  vs exérèse pleuro-pneumonectomie élargie (EPP) — controverse actuelle \
  (MARS2 trial, NICE 2024), immunothérapie de 1re ligne (nivolumab + ipilimumab)
→ Thymome / tumeurs médiastinales : résultats thymectomie VATS vs sternotomie \
  (oncologique + myasthénie gravis), classification WHO/Masaoka-Koga
→ Épanchement pleural malin : cathéter PleurX ambulatoire vs pleurodèse talc \
  hospitalisée (IPC vs talc slurry — données qualité de vie, durée de séjour, \
  coût-efficacité ; recommandations BTS/ESTS 2023)
→ ERAS thoracique : analgésie locorégionale (bloc serratus anterior, \
  ESPB — Erector Spinae Plane Block, bloc intercostal) vs péridurale thoracique, \
  mobilisation précoce, réduction durée de séjour
→ Complications majeures : fistule bronchique post-pneumonectomie/lobectomie, \
  empyème post-résection, chylothorax (traitement chirurgical vs conservateur \
  vs embolisation thoracique ductale), paralysie récurrentielle
→ Dépistage cancer poumon : résultats programmes LDCT (NELSON, DANTE, \
  recommandations HAS/INCa) et impact sur résécabilité des cancers dépistés
→ Alertes ANSM / FDA : agrafeuses endoscopiques pulmonaires/œsophagiennes \
  défectueuses, instruments de curage médiastinal, endoscopes bronchiques

REJETER :
→ Oncologie médicale pure (chimio/immuno sans aucune composante chirurgicale \
  ou staging chirurgical — relayer à oncologie)
→ Pneumologie médicale pure (BPCO, asthme, fibrose pulmonaire sans impact \
  sur résécabilité ou technique chirurgicale — relayer à pneumologie)
→ Anesthésie-réanimation sans lien direct avec chirurgie thoracique
→ Chirurgie cardiaque sans composante thoracique (CABG, valvulopathies \
  — relayer à chirurgie-cardiaque)
→ Radiothérapie/SBRT exclusive sans comparaison directe avec résection \
  (études SBRT seules pour patients inopérables — relayer à radiologie/oncologie)
→ Études endoscopiques digestives pures (œsophage — dilatations, POEM — sans \
  composante chirurgicale thoracique ou résection)

TERMINOLOGIE — employer sans guillemets ni définition :
VATS (Video-Assisted Thoracoscopic Surgery), RATS (Robot-Assisted — Da Vinci), \
lobectomie / segmentectomie anatomique / résection cunéiforme (wedge), \
pneumonectomie, bilobectomie, décortication pleurale, \
NSCLC (Non-Small Cell Lung Cancer), SCLC (Small Cell Lung Cancer), \
staging TNM 8e éd. (IASLC 2017) : T1a/b/c-T4, N0/N1/N2/N3, M0/M1a/b/c, \
pCR (complete pathological response), MPR (Major Pathological Response — résidu \
tumoral ≤ 10%), R0 (marges saines) / R1 (microscopique) / R2 (macroscopique), \
curage ganglionnaire systématique vs échantillonnage (MLND/SLND), \
EBUS (Endobronchial Ultrasound — staging médiastinal), médiastinoscopie, \
EGFR / ALK / ROS1 / KRAS G12C / MET exon 14 (mutations driver), \
PD-L1 TPS (Tumor Proportion Score — immunothérapie), \
ICI (Immune Checkpoint Inhibitor — anti-PD1/PD-L1/CTLA-4), \
DFS (Disease-Free Survival), OS (Overall Survival), \
MIE (Minimally Invasive Esophagectomy — laparoscopie + thoracoscopie), \
Ivor Lewis (thoracotomie + laparotomie, anastomose intrathoracique), \
McKeown (3 voies + anastomose cervicale), transhiatal (sans thoracotomie), \
fistule anastomotique (classification ISDE — grade A/B/C), \
EPP (Exérèse Pleuro-Pneumonectomie élargie — mésothéliome), \
P/D (Pleurectomie-Décortication — mésothéliome), MPM (Mésothéliome Pleural Malin), \
thymome (WHO type A/AB/B1/B2/B3/C = carcinome thymique), \
Masaoka-Koga (stade thymome : I/IIA/IIB/III/IVA/IVB), \
myasthénie gravis (MG — indication thymectomie), \
PleurX (cathéter pleural permanent ambulatoire), pleurodèse au talc, \
empyème (stades ATS : exsudatif / fibrinopurulent / organisé — \
  Light's criteria = diagnostic exsudat/transsudat, pas staging empyème), \
LDCT (Low-Dose CT scan — dépistage), \
ESPB (Erector Spinae Plane Block), bloc serratus anterior, \
thoracoscore / STS score (risque mortalité résection pulmonaire), \
SBRT / SABR (stéréotaxie — inopérables, comparaison chirurgie).

EXEMPLES DE RÉDACTION (style JTO / EJCTS / Annals of Thoracic Surgery — format cible) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai clinique résection pulmonaire :
  titre_court : "Segmentectomie non-inférieure à la lobectomie NSCLC ≤ 2 cm (CALGB 140503)"
  resume : "CALGB 140503 (RCT, N=697, NSCLC stade IA ≤ 2 cm, suivi médian 7 ans) : \
DFS à 5 ans 63,6 % (segmentectomie) vs 64,1 % (lobectomie) — HR 1,01 (IC95% 0,83–1,24), \
non-infériorité établie. OS à 5 ans 80,3 % vs 78,9 % (NS). VATS utilisée dans 57 % \
des cas. Marges R0 identiques (97 vs 98 %). Marge chirurgicale ≥ 2 cm imposée \
dans le groupe segmentectomie."
  impact_pratique : "En pratique : la segmentectomie anatomique devient le standard \
pour tout NSCLC ≤ 2 cm stade IA — à condition de marges ≥ 2 cm et curage N1/N2 complet."

Périopératoire / immuno-oncologie chirurgicale :
  titre_court : "Nivolumab néoadjuvant NSCLC résécable : pCR 24 % (CheckMate 816)"
  resume : "CheckMate 816 (RCT, N=358, NSCLC stade IB-IIIA résécable, \
3 cycles nivolumab + chimio vs chimio seule) : pCR 24,0 % vs 2,2 % \
(OR 13,94 ; IC95% 3,49–55,75 ; p<0,001). EFS médian non atteint vs 20,8 mois \
(HR 0,63 ; IC95% 0,43–0,91). Résection R0 : 83,2 % vs 75,5 %. \
Délai chirurgie non affecté. Profil de toxicité gérable."
  impact_pratique : "En pratique : nivolumab néoadjuvant + chimio — nouveau standard \
pour tout NSCLC stade IB-IIIA résécable avec PS 0-1, indépendamment du PD-L1."

Guideline / recommandation :
  titre_court : "ESTS 2024 : P/D préférée à l'EPP dans le mésothéliome pleural"
  resume : "ESTS Guidelines mésothéliome 2024 (EJCTS suppl.) : pleurectomie-décortication \
(P/D) recommandée en 1re intention vs EPP pour MPM épithélioïde résécable \
(recommandation forte, niveau B). Basé sur méta-analyse (N=2 147) : OS médian \
18,2 mois (P/D) vs 14,5 mois (EPP) — HR 0,79 (IC95% 0,64–0,98), mortalité \
péri-opératoire EPP 6,8 % vs P/D 2,1 % (p<0,001). Confirmation données MARS2."
  impact_pratique : "À retenir : abandon progressif de l'EPP sauf cas sélectionnés — \
P/D systématiquement discutée en RCP avant tout MPM épithélioïde."

Alerte sécurité dispositif :
  titre_court : "FDA : alerte agrafeuse Ethicon Echelon 60 — risques fistule bronchique"
  resume : "FDA Safety Communication (janv. 2026) : signalement de 42 cas de \
dysfonctionnement de l'agrafeuse endoscopique Ethicon Echelon 60 (lot xxxx) \
associés à 8 fistules bronchiques post-lobectomie (délai médian 4 jours post-op). \
ANSM avertie — en attente de décision EU. Mécanisme : défaut d'agrafage sur \
parenchyme pulmonaire épais (> 4 mm). Recommandation : vérification cartouche \
avant chaque utilisation, renfort suture bronchique systématique si suspicion."
  impact_pratique : "En pratique : signaler tout dysfonctionnement au fabricant, \
renforcer systématiquement la suture de la bronche souche sur les résections majeures."
"""

_SPECIALTY_ADDENDUM_ORTHOPEDIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CHIRURGIE ORTHOPÉDIQUE ET TRAUMATOLOGIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : chirurgien orthopédiste et traumatologue (CHU / clinique privée, \
France / Europe), maîtrisant arthroplastie (hanche, genou, épaule), \
chirurgie arthroscopique (LCA, coiffe des rotateurs, ménisques), \
traumatologie (fractures hanche, tibia, radius distal, rachis), \
chirurgie du rachis dégénératif et déformations, chirurgie du pied-cheville. \
Référentiels actuels : SOFCOT recommandations 2022-2024, EFORT guidelines, \
AAOS Clinical Practice Guidelines, NICE (UK), HAS recommandations. \
Essais pivots récents de référence : FAITH (fixation vis cancelleux vs DHS — \
fracture col fémoral non déplacée Garden I-II), \
HEALTH (PTH vs hémiarthroplastie — fracture col déplacée, patient ambulatoire), \
FLOW (acide tranexamique — fracture hanche, NEJM 2023), \
MOON cohort (LCA — greffons et résultats fonctionnels à 10 ans), \
RECORD 1-4 (rivaroxaban vs HBPM thromboprophylaxie arthroplastie), \
VERTIGO (vertébroplastie vs cyphoplastie vs traitement médical).

CRITÈRE DE PERTINENCE ORTHOPÉDIQUE :
"Ce résultat va-t-il modifier une indication opératoire, le choix d'un implant, \
un protocole ERAS, ou la stratégie de prise en charge dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une pratique \
déjà établie (ex. supériorité déjà connue d'un matériau ou d'une technique), \
population non représentative de la pratique FR/EU (cohorte mono-centrique asiatique \
sans équivalent anatomique ou ethnique), sous-groupe non pré-spécifié sur \
petits effectifs, études biomécaniques sans validation clinique.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Résultats fonctionnels et PROMs (Patient-Reported Outcome Measures) modifiant \
  le choix d'une technique : Oxford Hip/Knee Score, WOMAC, KOOS, DASH, Constant, \
  VISA-A, AOFAS, NRS douleur, PRWE (poignet)
→ Nouvelles données sur survie implantaire (registres nationaux ≥ 5 ans : \
  NJR, SKAR, AOANJRR, RNR France — arthroplastie hanche/genou/épaule)
→ Complications majeures : infection sur prothèse (PJI — Periprosthetic Joint Infection), \
  instabilité, descellement aseptique, fracture péri-prothétique, raideur post-op, \
  NERV (névralgie / paralysie post-arthroplastie)
→ ERAS orthopédique : protocoles analgésie multimodale, mobilisation précoce, \
  réduction transfusion (acide tranexamique IV/topique)
→ Thromboprophylaxie post-arthroplastie et fracture hanche : AOD vs HBPM, \
  durée optimale, schémas ambulatoires
→ Ligamentoplastie LCA : greffons (os-tendon-os vs gracilis-demi-tendineux vs \
  quadricipital), augmentation interne (ILA), retour au sport, taux de re-rupture
→ Prothèse épaule : prothèse inversée (PI) vs anatomique, indication rotator cuff \
  arthropathy, résultats fonctionnels (Constant-Murley, ASES), chirurgie robotique
→ Chirurgie du rachis : fusion vs non-fusion lombalgie dégénérative, \
  chirurgie mini-invasive (MIS-TLIF, XLIF, OLIF), décompression endoscopique, \
  implants dynamiques, résultats déformations adulte (scoliose)
→ Fractures de fragilité : prise en charge fracture col fémoral (arthroplastie vs \
  ostéosynthèse selon Garden), fracture vertébrale ostéoporotique (vertébroplastie \
  vs cyphoplastie vs traitement médical), protocoles FLS (Fracture Liaison Service)
→ Innovations implants : surfaces de glissement (céramique, polyéthylène hautement \
  réticulé UHMWPE), tiges sans ciment, cupules trabéculaires, impression 3D implants \
  sur-mesure, navigation/robotique (MAKO, ROSA, Stryker)
→ Alertes ANSM / FDA : rappels matériaux (tête métal-métal, cupule DePuy ASR, \
  implants défectueux), matériovigilance prothèses, instruments chirurgicaux

REJETER :
→ Articles purement fondamentaux (biologie osseuse, ostéogénèse, culture cellulaire) \
  sans validation clinique dans les 3 ans
→ Études animalières (modèles ovins, porcins, etc.) sans protocole clinique associé
→ Réhabilitation/kinésithérapie pure sans composante décision chirurgicale \
  (confier à médecine physique-réadaptation)
→ Rhumatologie médicale pure (polyarthrite rhumatoïde sous biothérapie, \
  lupus, vascularites — sauf si impact direct sur timing ou technique chirurgicale)
→ Résultats d'arthroplastie dans des populations sans équivalent en France \
  (ex. registres asiatiques avec anatomie fémoro-acétabulaire très différente)
→ Études biomécaniques in vitro / sur cadavre confirmant ce qui est déjà en \
  pratique courante (ex. nouvelle vis pédiculaire légèrement plus rigide)

TERMINOLOGIE — employer sans guillemets ni définition :
PTH (prothèse totale de hanche), PTG (prothèse totale de genou), \
PTE (prothèse totale d'épaule — inversée PI ou anatomique PA), \
hémiarthroplastie (prothèse céphalique — col fémoral fracturé), \
resurfaçage de hanche (Birmingham Hip Resurfacing — BHR), \
PJI (Periprosthetic Joint Infection — infection sur prothèse), \
DAIR (Débridement, Antibiotiques, Irrigation et Rétention d'implant), \
descellement aseptique / septique, ostéolyse péri-prothétique, \
fracture péri-prothétique (Vancouver B1/B2/B3 hanche, UCS/Unified Classification System épaule), \
ligamentoplastie LCA (os-tendon-os OTO, gracilis-demi-tendineux GDT, \
quadricipital QT), ILA (Internal Ligament Augmentation — Ligamys), \
méniscectomie partielle / suture méniscale, chondropathie (grade Outerbridge I-IV), \
microfractures / ACI (Autologous Chondrocyte Implantation) / MACI, \
coiffe des rotateurs : rupture partielle / transfixiante, réinsertion arthroscopique, \
tendon sus-épineux / sous-scapulaire / infra-épineux, \
ERAS (Enhanced Recovery After Surgery — orthopédique), \
acide tranexamique (ATX — antifibrinolytique per-op et post-op), \
NRS / EVA (douleur), WOMAC / KOOS / Oxford (scores fonctionnels genou-hanche), \
Constant-Murley / DASH / PRWE (scores épaule-poignet-main), \
Oxford Hip/Knee Score, VISA-A (tendon d'Achille), AOFAS (pied-cheville), \
registres nationaux : NJR (UK), SHAR/SKAR (Suède — hanche/genou), AOANJRR (Australie), RNR (France), \
Garden I-IV (col fémoral), AO/OTA (classification fractures), \
TLIF / PLIF / XLIF / MIS-TLIF / OLIF (arthrodèse lombaire voies d'abord), \
scoliose adulte (SRS-Schwab), FLS (Fracture Liaison Service), \
MAKO / ROSA (robots arthroplastie), navigation peropératoire, \
UHMWPE (polyéthylène hautement réticulé), céramique d'alumine / zircone, \
métal-métal (abandon — toxicité chrome-cobalt), cupule presse-fit / cimentée, \
tige sans ciment / cimentée, implant 3D / trabéculaire (titane poreux).

EXEMPLES DE RÉDACTION (style JBJS / Bone & Joint J / OTSR — format cible) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai clinique arthroplastie :
  titre_court : "PTH sans ciment vs cimentée : résultats à 10 ans (NJR 120 000 PTH)"
  resume : "Analyse du NJR (N=120 348 PTH primaires, suivi médian 10,2 ans) : \
taux de révision à 10 ans 4,1 % (sans ciment) vs 3,6 % (cimentée) — \
HR 1,15 (IC95% 1,08–1,22, p<0,001). Différence concentrée sur les < 65 ans \
(HR 1,31 ; IC95% 1,19–1,44) ; effacée chez les ≥ 75 ans (HR 1,03 ; IC95% 0,94–1,13). \
Résultats fonctionnels Oxford Hip Score comparables aux deux âges (delta 0,4 point, NS)."
  impact_pratique : "En pratique : consolide la préférence pour la PTH cimentée \
chez les patients < 65 ans actifs — à pondérer avec la qualité osseuse DXA."

Chirurgie arthroscopique / ligamentoplastie :
  titre_court : "Greffon quadricipital vs OTO pour LCA : re-rupture à 5 ans"
  resume : "RCT multicentrique (N=344, âge moyen 26 ans, sportifs compétition, \
suivi 5 ans) : re-rupture 6,9 % (QT) vs 8,1 % (OTO) — différence non significative \
(p=0,54). Retour au sport niveau antérieur : 72 % (QT) vs 71 % (OTO) à 24 mois. \
Douleur site de prélèvement significativement moindre avec QT à 6 mois \
(NRS 1,2 vs 2,4 ; p=0,003). KOOS sport à 5 ans identiques (88 vs 87 points)."
  impact_pratique : "En pratique : le QT s'impose comme alternative valide à l'OTO \
avec moindre morbidité de prélèvement — intégrer dans le choix selon morphotype."

Guideline / recommandation :
  titre_court : "SOFCOT 2024 : prothèse cimentée recommandée fracture col ≥ 75 ans"
  resume : "Recommandations SOFCOT 2024 (OTSR suppl.) : arthroplastie cimentée \
recommandée en 1re intention pour toute fracture col fémoral déplacée (Garden III-IV) \
chez les patients ≥ 75 ans (recommandation Grade A). Hémiarthroplastie vs PTH : \
PTH recommandée si patient autonome et espérance de vie ≥ 5 ans (Grade B). \
Basé sur méta-analyse (N=9 214) : révision à 5 ans 3,8 % (PTH) vs 9,1 % \
(hémiarthroplastie) — OR 0,40 (IC95% 0,31–0,51)."
  impact_pratique : "À retenir : arthroplastie cimentée systématique ≥ 75 ans — \
fin du débat tige sans ciment en urgence traumatologique."

Alerte matériovigilance :
  titre_court : "ANSM : retrait prothèse hanche métal-métal DePuy Pinnacle lot xxxx"
  resume : "ANSM (décision 8 mars 2026) : retrait du marché des prothèses \
DePuy Pinnacle tête métal-métal (lot xxxx) après signalement de 23 cas \
de pseudotumeurs (ALVAL — réaction aux débris métal-métal) en matériovigilance \
(délai médian 6,3 ans post-implantation). Environ 1 200 prothèses implantées \
en France depuis 2019. Surveillance recommandée : cobalt/chrome sanguin annuel \
+ IRM si symptômes."
  impact_pratique : "En pratique : identifier les patients porteurs du lot concerné \
et planifier dosage métal sanguin + consultation dans les 3 mois."
"""

_SPECIALTY_ADDENDUM_DERMATOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — DERMATOLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : dermatologue libéral ou hospitalier (CHU/CH), France / Europe. \
Activité polyvalente ou spécialisée en : dermatologie inflammatoire \
(psoriasis — plaques, pustuleux généralisé GPP, érythrodermique ; \
dermatite atopique/eczéma — modérée à sévère ; pemphigus vulgaire/foliacé, \
pemphigoïde bulleuse ; hidradénite suppurée — HS ; alopécie areata ; vitiligo), \
dermato-oncologie (mélanome — adjuvant/métastatique, BRAF/NRAS/NF1 status ; \
carcinome basocellulaire — CBC superficiel/nodulaire/avancé ; \
carcinome épidermoïde cutané — CE/CSCC ; \
lymphomes cutanés T — mycosis fongoïde MF, syndrome de Sézary SS, CD30+ ; \
mélanome muqueux, mélanome uvéal), dermatologie infectieuse et IST \
(HSV 1/2, VZV, HPV — condylomes, verrues, dysplasies cervicales suivi ; \
syphilis, gonorrhée, Mpox ; gale — traitement de masse et contacts ; \
dermatophyties, candidoses), acnéologie (acné vulgaire, acné conglobata, \
isotrétinoïne — programme PPP obligatoire en France). \
Référentiels actuels : EADV guidelines 2022-2024 (psoriasis, DA, mélanome, \
pemphigus), HAS recommandations (remboursement biologiques psoriasis/DA, \
protocole isotrétinoïne), SFD (Société Française de Dermatologie), \
EADO guidelines (European Association of Dermato-Oncology), \
European Consensus on Melanoma (ECM 2023), NCCN Melanoma/NMSC. \
Essais pivots récents de référence : \
DA : SOLO 1/2 (dupilumab NEJM 2016), BREEZE-AD1/2/7 (baricitinib), \
JADE MONO-1/2 (abrocitinib), Measure Up 1/2 (upadacitinib), \
ECZTRA 1/2 (tralokinumab), ADvocate 1/2 (lebrikizumab), \
Heads Up (upadacitinib vs dupilumab head-to-head). \
Psoriasis : UNCOVER-1/2/3 (ixekizumab), VOYAGE 1/2 (guselkumab), \
UltIMMa-1/2 (risankizumab), BE VIVID/BE SURE (bimekizumab), \
POETYK PSO-1/2 (deucravacitinib vs apremilast et adalimumab). \
GPP : EFFISAYIL-1 (spesolimab). \
Mélanome : CheckMate 238 (nivolumab adjuvant stade III), \
KEYNOTE-716 (pembrolizumab adjuvant stade IIB-IIC), \
RELATIVITY-047 (nivolumab+relatlimab mélanome avancé), COMBI-d/v \
(dabrafenib+trametinib BRAF+). CBC avancé : ERIVANCE (vismodegib), \
EMPOWER-BCC-1 (cemiplimab). CE cutané : EMPOWER-CSCC-1 (cemiplimab). \
CTCL : MAVORIC (mogamulizumab MF/SS), ALCANZA (brentuximab CD30+).

CRITÈRE DE PERTINENCE DERMATOLOGIE :
"Ce résultat va-t-il modifier un choix thérapeutique (initiation/switch biologique, \
séquence de ligne de traitement, seuil d'escalade), une indication de procédure \
cutanée (exérèse, Mohs, curage), ou la surveillance d'un effet indésirable \
dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une classe déjà \
établie sans nouvelle indication ni gain clinique mesurable, études in vitro \
sur mécanismes cutanés sans implication thérapeutique directe, \
épidémiologie descriptive sans recommandation opérationnelle, \
esthétique médicale (toxine botulique, acide hyaluronique injectables) \
sauf complication grave ou changement de pratique majeur.

FILTRES SPÉCIFIQUES DERMATOLOGIE :

→ RETENIR EN PRIORITÉ :
  Dermatologie inflammatoire :
  • Head-to-head biologiques : comparaisons directes dupilumab vs JAK inhibiteurs \
(abrocitinib, upadacitinib) dans la DA ; anti-IL-17 vs anti-IL-23 vs anti-IL-12/23 \
dans le psoriasis — résultats PASI 90/100, IGA, durée de réponse, profil de sécurité.
  • Nouvelles indications biologiques : dupilumab (HS, ABPA, prurigo nodulaire, \
polypose nasosinusienne — indications hors DA/asthme) ; spesolimab \
(anti-IL-36R — GPP flare, EFFISAYIL-1/2) ; bimekizumab (psoriasis ET DA en cours) ; \
deucravacitinib (TYK2 inhibiteur oral, POETYK PSO-1/2 vs apremilast et adalimumab).
  • Sécurité à long terme des JAK inhibiteurs : signal cardiovasculaire/thromboembolique \
(ORAL Surveillance), restriction EMA/ANSM — impact sur la présélection des patients.
  • Alertes ANSM sur immunosuppresseurs topiques (tacrolimus/pimecrolimus — \
réévaluation du signal lymphome ; corticoïdes topiques haute puissance ; \
fluorouracil 5-FU crème — alertes récentes EU sur effets systémiques) ; \
isotrétinoïne (PPP — modifications réglementaires programme grossesse).
  • Guidelines EADV mises à jour : psoriasis, DA, acné, mélanome, GPP.
  Dermato-oncologie :
  • Mélanome adjuvant stade II/III : pembrolizumab (KEYNOTE-716 stade IIB-IIC), \
nivolumab (CheckMate 238 stade III), nivolumab+ipilimumab vs nivolumab, \
adjuvant BRAF+ (dabrafenib+trametinib vs immunothérapie — séquence).
  • Mélanome métastatique : RELATIVITY-047 (nivolumab+relatlimab — anti-LAG3), \
combinaisons quadruples (anti-PD1+anti-CTLA4+anti-LAG3+anti-TIGIT), \
résultats OS finaux essais anti-BRAF/MEK (COMBI-d/v, coBRIM).
  • BCE avancé : cemiplimab (EMPOWER-BCC-1/2), vismodegib (ERIVANCE) ; \
résistance aux inhibiteurs de SMO (voie Hedgehog) et stratégies de recours.
  • CE cutané avancé (CSCC) : cemiplimab (EMPOWER-CSCC-1), pembrolizumab.
  • Lymphomes cutanés T : mogamulizumab (MAVORIC — MF/SS), \
brentuximab vedotin (ALCANZA — CD30+ CTCL), pembrolizumab dans le MF, \
nouvelles classifications WHO/ICC 2022 impactant la prise en charge.
  • Technique chirurgicale : marges d'exérèse mélanome (mise à jour guidelines), \
chirurgie de Mohs (CBC/CE — indications sur zones à risque), ganglion sentinelle \
mélanome (actualisation après DeCOG-SLT et MSLT-II).
  Réglementaire :
  • Modifications remboursement HAS biologiques dermatologie (critères d'accès \
dupilumab, baricitinib, upadacitinib, abrocitinib pour DA ; anti-IL-23/IL-17 psoriasis).
  • Alertes ANSM matériovigilance : lasers dermatologiques, photothérapie UVB, \
appareils dermatoscopie connectée.
  • JORF : arrêtés de remboursement nouveaux biologiques, modifications du PPP isotrétinoïne.

→ REJETER SANS HÉSITER :
  • Biologie fondamentale cutanée (immunologie mécanistique, génomique du kératinocyte, \
axe microbiome-peau) sans implication thérapeutique dans les 2 ans.
  • Phase 1-2 sans efficacité clinique démontrée sur endpoint patient.
  • Études monocentriques sur cohortes < 100 patients sans comparateur actif.
  • Médecine esthétique et injectables (toxine, AH, fillers) sauf signal de sécurité grave.
  • Épidémiologie descriptive incidence/prévalence sans recommandation opérationnelle.
  • Études in vitro sur modèles cellulaires cutanés sans transposabilité clinique immédiate.
  • Photoprotection, cosmétologie et soins hydratants — sauf essai comparatif de qualité \
modifiant un protocole de prévention ou de traitement adjuvant.

TERMINOLOGIE — employer sans guillemets ni définition :
PASI (Psoriasis Area and Severity Index) — PASI 75/90/100, IGA (Investigator's Global \
Assessment) 0/1, BSA (body surface area), DLQI (Dermatology Life Quality Index), \
EASI (Eczema Area and Severity Index), IGA-AD, PP-NRS (peak pruritus NRS), POEM, \
DA (dermatite atopique), HS (hidradénite suppurée), GPP (psoriasis pustuleux généralisé), \
dupilumab (anti-IL-4Rα — bloque IL-4 et IL-13 ; Dupixent), \
tralokinumab (anti-IL-13 ; Adtralza), lebrikizumab (anti-IL-13 ; Ebglyss), \
baricitinib (JAK1/JAK2 inhibiteur ; Olumiant), abrocitinib (JAK1 sélectif ; Cibinqo), \
upadacitinib (JAK1 sélectif ; Rinvoq), \
secukinumab (anti-IL-17A ; Cosentyx), ixekizumab (anti-IL-17A ; Taltz), \
bimekizumab (anti-IL-17A et IL-17F ; Bimzelx), brodalumab (anti-IL-17RA ; Kyntheum), \
ustékinumab (anti-IL-12/23 ; Stelara), guselkumab (anti-IL-23 ; Tremfya), \
risankizumab (anti-IL-23 ; Skyrizi), tildrakizumab (anti-IL-23 ; Ilumetri), \
deucravacitinib (inhibiteur TYK2 — oral ; Sotyktu), apremilast (IPD4 ; Otezla), \
spesolimab (anti-IL-36R ; Spevigo — GPP), \
mélanome : BRAF V600E/K mutation, NRAS, NF1, c-KIT, \
dabrafenib + trametinib (anti-BRAF + anti-MEK ; COMBI-d/v), \
vemurafenib + cobimetinib (anti-BRAF + anti-MEK), \
nivolumab (anti-PD1 ; Opdivo), pembrolizumab (anti-PD1 ; Keytruda), \
ipilimumab (anti-CTLA4 ; Yervoy), relatlimab (anti-LAG3 ; Opdualag — combo nivolumab), \
cemiplimab (anti-PD1 ; Libtayo — CBC avancé, CE cutané avancé), \
vismodegib (inhibiteur SMO — voie Hedgehog ; Erivedge), \
sonidegib (inhibiteur SMO ; Odomzo), \
mogamulizumab (anti-CCR4 ; Poteligeo — MF/SS), \
brentuximab vedotin (anti-CD30 ; Adcetris — CTCL CD30+), \
SLNB (ganglion sentinelle — sentinel lymph node biopsy), \
Mohs (chirurgie micrographique), marges R0 / chirurgie large, \
curage ganglionnaire (CLND — complete lymph node dissection), \
MF (mycosis fongoïde), SS (syndrome de Sézary), \
photothérapie NB-UVB (narrowband UVB), PUVA, \
isotrétinoïne (Curacné / Acnétane — PPP obligatoire), \
PPP (programme de prévention des grossesses — ANSM), \
5-FU topique (fluorouracil — kératoses actiniques, CE superficiels), \
imiquimod (Aldara — CBC superficiel, verrues anogénitales), \
cryothérapie, dermoscopie, réflectance confocale (RCM), \
MSLT (Multicenter Selective Lymphadenectomy Trial), \
ganglion sentinelle (SLNB), \
TIL (tumour-infiltrating lymphocytes — thérapie adoptive mélanome).

EXEMPLES DE RÉDACTION (style JAAD / BJD / JEADV / La Revue du Praticien Dermatologie) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


RCT biologique DA (head-to-head) :
  titre_court : "Upadacitinib vs dupilumab dans la DA sévère : Heads Up à 24 semaines"
  resume : "Heads Up (RCT, N=692, DA modérée-sévère, EASI ≥ 16, suivi 24 semaines) : \
EASI-75 à S16 : 71,0 % (upadacitinib 30 mg) vs 61,1 % (dupilumab 300 mg / 2 semaines) \
— p=0,006. IGA 0/1 : 50,5 % vs 38,7 % (p=0,002). PP-NRS ≥ 4 points : 50,7 % vs \
41,3 % (p=0,013). Infections graves : 1,7 % (upadacitinib) vs 0,3 % (dupilumab). \
Pas de différence mortalité ni événement thromboembolique à 24 semaines."
  impact_pratique : "En pratique : upadacitinib surpasse dupilumab sur les critères \
composites à 16 semaines — à pondérer avec un profil d'infection légèrement moins \
favorable et l'absence de données long terme (> 2 ans) vs dupilumab."

Guideline EADV psoriasis — mise à jour :
  titre_court : "EADV 2024 : bimekizumab et deucravacitinib intégrés en 1re ligne psoriasis"
  resume : "Mise à jour EADV guidelines psoriasis modéré-sévère (JEADV, 2024) : \
bimekizumab (anti-IL-17A et IL-17F) rejoint ixekizumab et guselkumab en 1re ligne \
systémique (recommandation forte, niveau A) sur la base de BE SURE et BE VIVID \
(PASI 90 ≥ 80 %, PASI 100 ≥ 65 % à 16 semaines vs adalimumab et ustekinumab). \
Deucravacitinib (TYK2 inhibiteur oral) introduit en alternative orale aux anti-IL-17/23 \
chez les patients refusant les injections (POETYK PSO-1/2, PASI 75 : 53-58 % vs \
placebo 7-8 %, vs apremilast 30 %). Méthotrexate et ciclosporine reclassés en \
traitement relais/pont plutôt qu'en 1re ligne biologique."
  impact_pratique : "En pratique : le choix entre anti-IL-17A/F, anti-IL-23 et TYK2 \
oral peut maintenant se faire selon le profil patient (mode d'administration, \
comorbidités, préférence) — tous niveau A selon les nouvelles guidelines."

Mélanome adjuvant stade IIB-IIC :
  titre_court : "Pembrolizumab adjuvant stade IIB-IIC : KEYNOTE-716 OS à 4 ans"
  resume : "KEYNOTE-716 (RCT, N=976, mélanome résécable stade IIB-IIC, suivi médian \
4 ans) : survie sans récidive (RFS) à 4 ans 72,1 % (pembrolizumab) vs 64,2 % \
(placebo) — HR 0,64 (IC95% 0,50–0,84 ; p=0,001). Survie globale à 4 ans : 89,4 % vs \
86,2 % (HR 0,73 ; IC95% 0,50–1,07 ; p non significatif au seuil prédéfini). \
Effets indésirables immunologiques grade ≥ 3 : 15,5 % (pembrolizumab)."
  impact_pratique : "En pratique : le pembrolizumab adjuvant est indiqué et remboursé \
(AMM EMA, août 2023) dans les mélanomes stade IIB-IIC réséqués — réduire de 36 % \
le risque de récidive, à peser contre le profil de toxicité immunologique."

Alerte ANSM :
  titre_court : "ANSM : fluorouracil 5 % crème (Efudix) — risque systémique, restrictions prescripteurs"
  resume : "ANSM/EMA (2021, rappel mars 2026) : restriction d'utilisation du \
fluorouracil 5 % crème (Efudix) après 25 cas d'effets systémiques graves en Europe \
(cardiotoxicité, diarrhée, mucite) chez des patients porteurs d'un déficit en \
dihydropyrimidine déshydrogénase (DPD — prévalence 3-5 % en population générale). \
Désormais : test DPD obligatoire avant initiation, prescription réservée aux \
spécialistes (dermatologue, oncologue), contre-indication absolue si déficit DPD \
complet (homozygote)."
  impact_pratique : "En pratique : tester le statut DPD (uracilémie plasmatique) \
avant toute prescription de 5-FU topique — le déficit partiel (hétérozygote) impose \
une réduction de dose ou un traitement alternatif (imiquimod, cryothérapie)."
"""

_SPECIALTY_ADDENDUM_ENDOCRINOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — ENDOCRINOLOGIE, DIABÉTOLOGIE ET MALADIES MÉTABOLIQUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : endocrinologue-diabétologue (CHU / cabinet libéral, France / Europe), \
prenant en charge diabète de type 1 et 2, obésité, thyroïde, surrénales, hypophyse, \
parathyroïdes, ostéoporose, SOPK et troubles gonadiques.
Référentiels actuels : recommandations SFE (Société Française d'Endocrinologie), \
consensus EASD/ADA (Standards of Care in Diabetes 2025), ESE Clinical Practice \
Guidelines, guidelines ETA (European Thyroid Association) 2023-2024, recommandations \
HAS (diabète, obésité, thyroïde), ESC/EASD guidelines on Diabetes and CVD 2023, \
IOF/ESCEO ostéoporose 2023.
Essais pivots récents de référence — diabète/obésité : EMPA-REG OUTCOME \
(empagliflozine CV), CANVAS (canagliflozine), DECLARE-TIMI 58 (dapagliflozine), \
LEADER (liraglutide CV), SUSTAIN-6 (sémaglutide CV), SELECT (sémaglutide 2,4 mg \
obésité sans diabète — réduction MACE), SURMOUNT-1/2/3/4 (tirzepatide obésité), \
SURPASS-CVOT (tirzepatide CV), STEP 1-5 (sémaglutide obésité), DAPA-HF, \
EMPEROR-Reduced/Preserved (iSGLT2 insuffisance cardiaque), DELIVER (dapagliflozine IC), \
FLOW (sémaglutide néphroprotection — réduction DFG et CV), FIDELIO-DKD / \
FIGARO-DKD (finerenone IRC+DT2), ONWARDS 1-6 (insuline icodec hebdomadaire).
Essais pivots récents de référence — ostéoporose : FREEDOM + Extension (dénosumab), \
ARCH (romosozumab vs alendronate — réduction fractures vertébrales 48 %), \
FRAME (romosozumab vs placebo), VERO (tériparatide vs risédronate), \
TULIP (abaloparatide vs tériparatide).
Essais pivots récents de référence — hypophyse / surrénales : LINC-3/4 \
(osilodrostat — syndrome de Cushing), SONICS (osilodrostat open-label), \
ACROBAT / GRAVITATE (lanréotide + pegvisomant — acromégalie), \
LIBRETTO-531 (selpercatinib — cancer médullaire RET-muté).

CRITÈRE DE PERTINENCE ENDOCRINOLOGIE :
"Ce résultat va-t-il modifier un choix thérapeutique, un objectif glycémique, \
un critère de substitution hormonal ou une stratégie de suivi dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : confirmateur d'une pratique établie sans \
gain de précision clinique, sous-groupe non pré-spécifié sur < 200 patients, \
population asiatique sans validation EU (ex. IMC moyen 25 kg/m² incompatible \
avec obésité FR), bénéfice uniquement biologique sans endpoint clinique \
(HbA1c seul sans endpoint CV/rénal ni QdV pour une molécule déjà commercialisée).

DOMAINES PRIORITAIRES :
  Diabète de type 2 et obésité :
  • Nouveaux agonistes GLP-1 et double/triple agonistes (tirzepatide GLP-1/GIP — \
Mounjaro/Zepbound ; retatrutide, mazdutide GLP-1/GIP/glucagon — essais phase 3) : \
données MACE, perte de poids, néphroprotection, effets indésirables GI, \
abandon de traitement.
  • iSGLT2 : nouvelles extensions d'indication AMM EU (IC à FEVG préservée \
EMPEROR-Preserved, IRC stade G3-G4 DAPA-CKD), séquences iSGLT2 + GLP-1 selon \
comorbidité CV/rénale/obésité (algorithme EASD/ADA 2025).
  • Obésité : essais phase 3 oraux (orforglipron — GLP-1 oral non peptidique, \
cagrilintide — analogue amyline), résultats long terme chirurgie bariatrique \
(5-10 ans : sleeve vs bypass Roux-en-Y), remboursement Wegovy/Mounjaro FR.
  • Insulinothérapie : icodec hebdomadaire (Awiqli — AMM EU 2023, ONWARDS 1-6), \
systèmes closed-loop hybrides DT1 (780G, Control-IQ, CamAPS Fx — données vie réelle \
HbA1c + TIR + sécurité).
  • ANSM / HAS : alertes pénuries GLP-1 agonistes, rappels CGM (FreeStyle Libre, \
Dexcom G7), remboursement nouvelles molécules.

  Thyroïde :
  • Cancer différencié : déescalade surveillance active (cancer papillaire bas risque \
< 1 cm), cibles TSH post-thyroïdectomie selon risque ATA/ETA 2023, thérapies ciblées \
(selpercatinib Retsevmo — LIBRETTO-531, RET-muté / réarrangé).
  • Cancer médullaire : vandetanib, cabozantinib, selpercatinib.
  • Cancer anaplasique (ATC) : dabrafenib + trametinib (BRAF V600E muté — AMM FDA \
2018, accès compassionnel EU).
  • Hypothyroïdie : LT4 seule vs LT4+LT3 (données méta-analyses sur QdV), \
cibles TSH selon l'âge (> 65 ans : TSH haute normale acceptable).
  • Maladie de Basedow : durée optimale antithyroïdiens (ATD 18-24 mois, \
taux de rémission à 5 ans), ophtalmopathie de Basedow \
(téprotumumab Tepezza — pas AMM EU à ce jour ; rituximab OB en accès ART).
  • Nodules : EU-TIRADS 2023, hémithyroïdectomie vs totalisation, classification \
Bethesda + tests moléculaires (Afirma, ThyroSeq).

  Surrénales :
  • Syndrome de Cushing endogène : osilodrostat (Isturisa — inhibiteur 11β-OHD, \
LINC-3/4/SONICS), métyrapone, pasireotide (Signifor — maladie de Cushing centrale), \
radiochirurgie Gamma Knife post-adénomectomie.
  • Hyperaldostéronisme primaire (syndrome de Conn) : cathétérisme veineux surrénalien \
(CVS — latéralisation avant surrénalectomie), finerenone (Kerendia — FIDELIO/FIGARO), \
lorundrostat (inhibiteur CYP11B2 sélectif — essais phase 3).
  • Incidentalome surrénalien : algorithme sécrétoire (CLU, TFD 1 mg, RAR), \
surveillance vs chirurgie selon taille/caractéristiques TDM (critères ESE 2023).
  • Insuffisance surrénalienne : hydrocortisone dual-release (Plenadren) vs \
conventionnelle, éducation thérapeutique crise addisonienne (carte d'urgence SFE).
  • Phéochromocytome / paragangliome : 177Lu-DOTATATE (NETSPOT — thérapie PRRT), \
classification WHO 2022 (tous les phéo considérés à potentiel malin).

  Hypophyse :
  • Acromégalie : analogues somatostatine (lanréotide Somatuline, octréotide LAR) + \
pegvisomant (Somavert) en combinaison (ACROBAT/GRAVITATE — IGF-1 normalisation \
> 80 % en combinaison vs 55 % mono), pasireotide LAR (Signifor LAR — résistants \
aux SSA classiques). Critères de guérison post-chirurgie transsphénoïdale.
  • Prolactinome : résistance à la cabergoline (critères ESE 2023), prolactinome \
géant agressif (témozolomide, immunothérapie — données de cohorte).
  • Adénomes non fonctionnels : surveillance IRM vs chirurgie transsphénoïdale \
(critères EAONO 2023).
  • Maladie de Cushing centrale : remission criteria (CLU, cortisol matinal) \
post-opératoire, osilodrostat en 2e ligne.

  Ostéoporose :
  • Romosozumab (Evenity — anti-sclérostine, 210 mg/mois sc) : ARCH (réduction \
fractures vertébrales −48 % vs alendronate), indication post-ménopausique très \
haut risque fracturaire (≥ 2 fractures ou T-score ≤ −3,5).
  • Tériparatide (Forsteo) et abaloparatide (Eladynos) : durée max 24 mois, \
transition obligatoire vers antirésorbeur (dénosumab ou bisphosphonate).
  • Dénosumab (Prolia) : rebond osseux à l'arrêt — séquencement \
bisphosphonate obligatoire. Dénosumab extension 10 ans (FREEDOM Extension).
  • Ostéoporose masculine : données post-ADT (androgen deprivation therapy — \
cancer prostate), dénosumab, tériparatide.
  • HAS 2019 / IOF-ESCEO 2023 : score FRAX, indications remboursement, \
séquencement anabolique → antirésorbeur.

  Réglementaire :
  • HAS : recommandations prise en charge médicamenteuse DT2 (2024), obésité (2022), \
cancer thyroïde différencié (2022), ostéoporose post-ménopausique.
  • ANSM : alertes pénuries insulines / GLP-1 agonistes, rappels dispositifs CGM, \
interactions médicamenteuses GLP-1 + anticoagulants.
  • JORF : arrêtés de remboursement (tirzepatide, icodec, osilodrostat, selpercatinib, \
romosozumab).

→ REJETER SANS HÉSITER :
  • HbA1c seul comme endpoint primaire sans endpoint CV/rénal ni QdV si la molécule \
est commercialisée depuis > 5 ans.
  • Études pharmacocinétiques / PK-PD sans endpoint clinique patient-relevant.
  • Diabète T2 phase 1-2 sans efficacité démontrée sur endpoint clinique.
  • Études transversales épidémiologiques incidence/prévalence sans recommandation \
opérationnelle.
  • Analogues insuline existants sans nouveau signal (sécurité, formulation, indication).
  • Cohortes monocentriques < 100 patients sur molécules connues sans signal sécurité.
  • Endocrinologie reproductive (SOPK, ménopause) — sauf modification majeure de \
guidelines SFE/ESE ou signal de sécurité important.
  • Études in vitro ou modèles animaux sans transposabilité clinique < 2 ans.
  • Supplémentation en vitamine D seule (sans impact fracturaire ou CV démontré \
sur endpoint primaire).

TERMINOLOGIE — employer sans guillemets ni définition :
DT1 / DT2 (diabète de type 1 / 2), HbA1c (hémoglobine glyquée), \
TIR (Time In Range — % temps 70-180 mg/dL), TAR (Time Above Range), \
TBR (Time Below Range), GMI (Glucose Management Indicator), \
CGM (Continuous Glucose Monitoring — FreeStyle Libre, Dexcom G7), \
SAP (Sensor-Augmented Pump), closed-loop (boucle fermée hybride), \
DFG (débit de filtration glomérulaire — mL/min/1,73 m²), \
MACE (Major Adverse Cardiovascular Events — IDM non fatal + AVC + décès CV), \
IC-FEr / IC-FEp / IC-FEm (insuffisance cardiaque à FEVG réduite / préservée / midrange), \
IMC (indice de masse corporelle, kg/m²), \
bariatrique (sleeve gastrectomy / bypass Roux-en-Y, BPG), \
MODY (Maturity-Onset Diabetes of the Young), \
iSGLT2 : empagliflozine (Jardiance), dapagliflozine (Forxiga), \
canagliflozine (Invokana), ertugliflozine (Steglatro), \
agonistes GLP-1 : sémaglutide (Ozempic 0,5-2 mg sc / Wegovy 2,4 mg sc / \
Rybelsus oral), liraglutide (Victoza 1,8 mg / Saxenda 3 mg), \
dulaglutide (Trulicity), exénatide LAR (Bydureon), \
GLP-1/GIP dual agoniste : tirzepatide (Mounjaro 2,5-15 mg / Zepbound 2,5-15 mg), \
insuline dégludec hebdomadaire : icodec (Awiqli), \
insulines basales : dégludec (Tresiba U100/U200), glargine U100 (Lantus) / \
U300 (Toujeo), dégludec+liraglutide (Xultophy), \
iDPP4 : sitagliptine, vildagliptine, saxagliptine, alogliptine, linagliptine, \
TSH (thyréostimuline), T4L / T3L, anti-TPO / anti-TG, \
eu-/hypo-/hyperthyroïdie, maladie de Basedow, \
OB (ophtalmopathie de Basedow — TAO, Thyroid-Associated Orbitopathy), \
EU-TIRADS (classification échographique nodule — 2023), \
BRAF V600E (mutation cancer papillaire thyroïdien), \
RET (proto-oncogène — cancer médullaire / cancer thyroïde RET-muté), \
selpercatinib (Retsevmo — inhibiteur RET sélectif), \
vandetanib (Caprelsa), cabozantinib (Cometriq / Cabometyx), \
CLU (cortisol libre urinaire), TFD (test de freination à la dexaméthasone 1 mg / 2×2 mg), \
ACTH plasmatique, RAR (ratio aldostérone/rénine), CVS (cathétérisme veineux surrénalien), \
osilodrostat (Isturisa — inhibiteur 11β-hydroxylase), \
finerenone (Kerendia — antagoniste MR non stéroïdien), \
GH (growth hormone), IGF-1 (insulin-like growth factor-1), \
lanréotide (Somatuline Autogel 60-120 mg), octréotide LAR (Sandostatin LAR 10-30 mg), \
pegvisomant (Somavert — antagoniste GH-R), \
pasireotide LAR (Signifor LAR — SSA pan-somatostatine), \
FRAX (Fracture Risk Assessment Tool), \
DXA (absorptiométrie biphotonique — T-score / Z-score), \
romosozumab (Evenity — anti-sclérostine, 210 mg/mois sc), \
tériparatide (Forsteo — PTH 1-34, 20 µg/j sc), \
abaloparatide (Eladynos — PTHrP analogue), \
dénosumab (Prolia — anti-RANKL, 60 mg / 6 mois), \
ADT (androgen deprivation therapy — cancer prostate, ostéoporose masculine), \
177Lu-DOTATATE (NETSPOT — thérapie PRRT phéo/paragangliome).

EXEMPLES DE RÉDACTION (style Diabetes Care / Lancet Diabetes Endocrinol / JCEM / \
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\

Ann Endocrinol — résultat d'abord, chiffres en contexte) :

RCT iSGLT2 insuffisance cardiaque à FEVG préservée :
  titre_court : "Empagliflozine dans l'IC-FEp : EMPEROR-Preserved, 26 mois"
  resume : "EMPEROR-Preserved (RCT, N=5 988, IC-FEp/IC-FEm FEVG ≥ 40 %, suivi médian \
26 mois) : réduction de 21 % du critère combiné hospitalisation CV pour IC + décès CV \
sous empagliflozine vs placebo (HR 0,79 ; IC95% 0,69–0,90 ; p < 0,001), chez DT2 et \
non-DT2 (bénéfice similaire). Réduction des hospitalisations pour IC : HR 0,73 \
(IC95% 0,61–0,88). Pas de bénéfice significatif sur la mortalité CV isolée."
  impact_pratique : "En pratique : empagliflozine (et dapagliflozine — DELIVER) \
disposent d'une AMM EU dans l'IC-FEp — à initier en coordination avec le cardiologue \
chez tout DT2 avec IC-FEp documentée, indépendamment du contrôle glycémique."

Guideline EASD/ADA 2025 — algorithme DT2 avec obésité :
  titre_court : "EASD/ADA 2025 : tirzepatide en 1re intention chez DT2 avec obésité"
  resume : "Mise à jour du consensus de gestion hyperglycémique EASD/ADA (Diabetes Care, \
2025) : chez le patient DT2 avec obésité (IMC ≥ 30 kg/m²), le tirzepatide \
(GLP-1/GIP dual agoniste) devient une option de 1re intention aux côtés du \
sémaglutide 2 mg, avec une perte de poids médiane supérieure (SURPASS-2 : −2,3 points \
d'HbA1c et −7,8 kg vs sémaglutide 1 mg à 40 semaines). L'algorithme intègre la \
comorbidité dominante : IC → iSGLT2 en premier ; IRC avec DFG 20-45 mL/min → \
finerenone si UACR ≥ 30 mg/g ; athérosclérose établie → sémaglutide / dulaglutide."
  impact_pratique : "En pratique : le choix du premier agent après metformine est \
désormais guidé par la comorbidité dominante (CV, rénal, obésité) — le consensus \
EASD/ADA 2025 rend cet algorithme opposable en consultation."

Essai pivot insuline hebdomadaire — icodec :
  titre_court : "Insuline icodec 1/semaine : ONWARDS 1-6 — non-infériorité vs dégludec"
  resume : "Programme ONWARDS (6 RCTs, N ~ 4 500 au total, DT1 et DT2, suivi \
26-52 semaines) : icodec 1 injection/semaine vs insuline basale quotidienne (dégludec \
ou glargine U100). Non-infériorité atteinte dans 5/6 essais sur HbA1c ; supériorité \
dans ONWARDS 1 (DT2, Δ HbA1c −0,19 % ; p=0,002) et ONWARDS 3 (sans insuline basale \
préalable). TBR < 54 mg/dL légèrement augmenté dans ONWARDS 1 \
(0,53 % vs 0,22 % ; Δ +0,31 %). AMM EMA octroyée (Awiqli, août 2023)."
  impact_pratique : "En pratique : icodec simplifie l'initiation insuline basale chez le \
DT2 avec faible observance quotidienne — à proposer en priorité lorsque l'oubli de \
dose est le principal frein à l'insulinisation."

Alerte ANSM — pénurie GLP-1 :
  titre_court : "ANSM/HAS : priorisation GLP-1 agonistes — tensions d'approvisionnement 2025"
  resume : "ANSM (communication jan. 2025) : face aux tensions persistantes sur \
sémaglutide (Ozempic, Wegovy) et liraglutide (Victoza, Saxenda), la HAS recommande \
de réserver la prescription aux DT2 avec indication CV ou rénale documentée \
(MACE ≥ 1, IRC stade G3+, obésité IMC > 35 kg/m²) et de ne pas initier dans les \
formes non compliquées sans enjeu CV/rénal. Tirzepatide (Mounjaro) disponible hors \
rupture — alternative recommandée. Prescription hors-AMM à visée pondérale seule \
formellement déconseillée en période de tension."
  impact_pratique : "En pratique : identifier les patients sous GLP-1 sans indication \
CV/rénale et proposer un basculement vers tirzepatide ou dulaglutide \
(disponibles) — conserver sémaglutide pour les indications prioritaires documentées."
"""

_SPECIALTY_ADDENDUM_GASTROENTEROLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — GASTROENTÉROLOGIE, HÉPATOLOGIE ET ENDOSCOPIE DIGESTIVE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : gastroentérologue-hépatologue (CHU / cabinet libéral, France / Europe), \
prenant en charge MICI (maladie de Crohn + colite ulcéreuse), maladies hépatiques \
(MASLD/MASH, CBP, PSC, hépatites virales, CH, cirrhose), cancers digestifs (CCR, CH, \
pancréas, estomac, œsophage), endoscopie diagnostique et interventionnelle, RGO, \
maladies fonctionnelles (SII, dyspepsie).
Référentiels actuels : ECCO guidelines 2023-2024 (MICI), EASL Clinical Practice \
Guidelines 2023-2024 (hépatologie), ESGE guidelines 2023-2024 (endoscopie), \
recommandations SNFGE/HAS (France), consensus Maastricht VI/Florence 2022 (H. pylori), \
ASCO/ESMO guidelines CCR et cancers digestifs, AASLD Practice Guidance 2023-2024.
Essais pivots récents de référence — MICI : VARSITY (vedolizumab vs adalimumab RCT CU — \
réponse clinique 31,3 % vs 22,5 % à 52 sem), GEMINI 1/2/3 (vedolizumab), \
UNIFI (ustekinumab CU), ADVANCE/MOTIVATE (risankizumab MC induction), \
STARDUST (risankizumab MC), LUCENT-1/2 (mirikizumab CU — rémission clinique 24,2 % \
vs 13,3 % à 52 sem), VIVID-1 (mirikizumab MC), U-ACHIEVE (upadacitinib CU), \
U-EXCEL/U-EXCEED (upadacitinib MC), TRUE NORTH (ozanimod CU), \
ELEVATE UC 12/52 (etrasimod CU), SELECTION (filgotinib CU), OCTAVE (tofacitinib CU), \
CALM (MC tight control treat-to-target), SONIC (infliximab + azathioprine MC).
Essais pivots récents de référence — hépatologie / MASH : \
MAESTRO-NASH (resmetirom — Rezdiffra — 1er traitement approuvé FDA mars 2024 MASH F2-F3 : \
réduction fibrothique ≥1 stade sans aggravation MASH 25,9 % vs 14,2 %), \
POISE (obeticholic acid CBP — amélioration ALP > 15 % et < ULN), \
ELATIVE (elafibranor CBP — PPARα/δ — ALP normalisation 15,7 % vs 2,7 %), \
RESPONSE (seladelpar CBP — PPARδ), IMbrave150 (atezolizumab + bevacizumab CH \
avancé vs sorafenib — SG 19,2 vs 13,4 mois), HIMALAYA (tremelimumab 300 mg \
dose unique + durvalumab CH — STRIDE regimen), PRODIGE 24 (FOLFIRINOX adjuvant \
pancréas vs gemcitabine — SG 54,4 vs 35,0 mois), TOPAZ-1 (durvalumab + gemcitabine \
voies biliaires avancées), KEYNOTE-590 (pembrolizumab + CT œsophage/JOG).
Essais pivots récents de référence — cancers colorectaux : \
MOSAIC (FOLFOX adjuvant CCR — référence stade III), OPTIMOX (FOLFOX intermittent), \
FIRE-3 / CALGB 80405 (cetuximab vs bevacizumab 1re ligne RAS-WT), \
BEACON (encorafenib + cetuximab BRAF V600E mCCR), \
KEYNOTE-177 (pembrolizumab MSI-H/dMMR CCR — SG médiane non atteinte vs CT).

CRITÈRE DE PERTINENCE GASTROENTÉROLOGIE :
"Ce résultat va-t-il modifier un choix de biothérapie, un algorithme de séquençage \
thérapeutique, un critère de surveillance ou une stratégie endoscopique dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : comparaison de deux molécules déjà séquencées \
sans nouvelle indication, étude de cohorte monocentrique < 80 patients sur une molécule \
commercialisée, endpoint biologique seul sans endpoint clinique (ex. calprotectine seule \
sans rémission endoscopique), épidémiologie descriptive sans recommandation opérationnelle.

DOMAINES PRIORITAIRES :

  MICI — maladie de Crohn et colite ulcéreuse :
  • Biothérapies et petites molécules — séquençage post-anti-TNF :
    Vedolizumab (Entyvio — anti-α4β7 intégrine, sc et IV), ustekinumab (Stelara — \
    anti-IL-12/IL-23 p40), risankizumab (Skyrizi — anti-IL-23 p19, MC), \
    mirikizumab (Omvoh — anti-IL-23 p19, CU), guselkumab (Tremfya — anti-IL-23 p19, \
    en évaluation MICI), ozanimod (Zeposia — modulateur S1P, CU), \
    etrasimod (Velsipity — modulateur S1P, CU), filgotinib (Jyseleca — JAK1, CU), \
    upadacitinib (Rinvoq — JAK1, MC et CU), tofacitinib (Xeljanz — JAK1/3, CU).
  • Treat-to-target (T2T) : cible — rémission endoscopique (absence d'ulcères MC, \
    Mayo endoscopique ≤ 1 CU) + rémission biologique (calprotectine fécale < 150-250 µg/g \
    + CRP normale) ; monitoring trimestriel en phase d'induction, semestriel en entretien.
  • Thérapies combinées (biothérapie + IMM) et positionnement des biosimilaires \
    (infliximab CT-P13, adalimumab ABP 501 — données switch). \
    Chirurgie MC : résection iléo-cæcale vs traitement médical (LIRIC trial), \
    résection prophylactique anastomose (proctocolectomie CU — pouchite, IPAA).
  • ANSM/HAS : alertes biothérapies (PML natalizumab, réactivation HBV, lymphomes JAKi), \
    remboursement mirikizumab (CU) et upadacitinib (MC), biosimilaires.

  MASLD / MASH (ex-NAFLD / NASH) :
  • Resmetirom (Rezdiffra — agoniste TRβ sélectif, 80-100 mg/j po) : \
    AMM FDA mars 2024 — MASH avec fibrose significative (F2-F3) ; réduction fibrose \
    ≥ 1 stade sans aggravation MASH 25,9 % vs 14,2 % (MAESTRO-NASH) ; \
    EMA en évaluation 2024-2025. Critère diagnostic : biopsie ou FibroScan + MRI-PDFF.
  • Critères MASLD (2023) : stéatose hépatique + ≥1 facteur métabolique (IMC, HTA, \
    DT2, TG élevés, HDL bas) ; MASH = MASLD avec activité nécro-inflammatoire ≥ grade 1.
  • Autres molécules en phase 3 : lanifibranor (IVA337 — pan-PPAR agoniste), \
    semaglutide 2,4 mg sc (ESSENCE — résultats attendus 2025-2026), \
    pegozafermin (FGF21 analogue).
  • Fibrose hépatique : FibroScan (LSM — kPa), FIB-4, APRI, ELF test ; \
    biopsie réservée aux cas ambigus. Référentiel EASL 2023.

  Hépatologie :
  • Cirrhose biliaire primitive (CBP) : obeticholic acid / acide obéticholique \
    (Ocaliva — agoniste FXR, 5-10 mg/j), elafibranor (Iqirvo — agoniste PPARα/δ, \
    80 mg/j — AMM FDA/EU 2024), seladelpar (Livdelzi — agoniste PPARδ — AMM FDA 2024) \
    en 2e ligne après AUDC (acide ursodéoxycholique) insuffisant.
  • Cholangite sclérosante primitive (PSC) : aucun traitement modifiant la maladie à \
    ce jour — données norUDCA (acide norursodéoxycholique), vancomycine orale pédiatrique \
    (données préliminaires). Surveillance cholangiocarcinome (bili-IRM ann., Ca19-9).
  • Hépatite B chronique : ténofovir alafénamide (TAF — Vemlidy 25 mg), entécavir \
    (Baraclude 0,5 mg) ; VHD (hépatite delta) : bulevirtide (Hepcludex 2 mg sc — \
    AMM EU 2020, seul traitement approuvé).
  • Hépatite C : traitement par DAA (sofosbuvir/velpatasvir — Epclusa, \
    glécaprévir/pibrentasvir — Maviret) — RVS > 95-98 % ; plus de nouveaux essais \
    majeurs, focus sur les populations difficiles (cirrhose décompensée, \
    retraitement après échec).
  • Carcinome hépatocellulaire (CH) : atezolizumab + bevacizumab (Tecentriq + \
    Avastin — IMbrave150, 1re ligne avancée — SG 19,2 mois vs 13,4 mois sorafenib), \
    tremelimumab 300 mg + durvalumab (HIMALAYA — STRIDE, SG 16,4 mois vs 13,8 mois), \
    sorafenib (Nexavar — 2e ligne si CI immunothérapie), lenvatinib (Lenvima — non-inf \
    sorafenib). Indications transplantation : critères de Milan (1 nodule ≤ 5 cm ou \
    ≤ 3 nodules ≤ 3 cm) vs critères étendus (UCSF, up-to-7).

  Cancers digestifs :
  • Cancers colorectaux (CCR) : dépistage (FIT biannuel 50-74 ans, coloscopie si \
    positif), polypectomie endoscopique (guidelines ESGE 2022 polypes), \
    traitement stade III adjuvant (FOLFOX 12 cycles), stade IV (FOLFOX/FOLFIRI + \
    bevacizumab ou cétuximab/panitumumab si RAS-WT), BRAF V600E : encorafenib + \
    cetuximab (BEACON), MSI-H/dMMR : pembrolizumab 1re ligne (KEYNOTE-177) ou \
    nivolumab. Syndrome de Lynch : surveillance coloscopique tous les 1-2 ans.
  • Cancer du pancréas : FOLFIRINOX adjuvant 12 cycles (PRODIGE 24, SG 54,4 mois), \
    nab-paclitaxel + gemcitabine si FOLFIRINOX contre-indiqué. Localement avancé : \
    FOLFIRINOX → chirurgie si downstaging (PREOPANC-2).
  • Voies biliaires : durvalumab + gemcitabine (TOPAZ-1, 1re ligne cholangiocarcinome \
    avancé — SG 12,8 vs 11,5 mois). Altérations IDH1/FGFR2 : ivosidenib (Tibsovo) / \
    pemigatinib (Pemazyre).
  • Œsophage et jonction œsogastrique (JOG) : pembrolizumab + CT (KEYNOTE-590, \
    œsophage avancé — SG 12,4 vs 9,8 mois), nivolumab (CheckMate 649, adénoK JOG \
    CPS ≥ 5). Barrett : RFA (radiofréquence ablation) si dysplasie LG/HG.

  Endoscopie digestive :
  • ESGE guidelines 2023-2024 : polypectomie / mucosectomie (EMR/ESD), CPRE \
    (prophylaxie pancréatite post-CPRE : indométacine rectale + hydratation IV), \
    surveillance coloscopique post-polypectomie (intervalles selon risque).
  • Nouvelles techniques : coloscopie assistée par IA (détection polypes — CADe/CADx, \
    données poolées sensitivity > 92 %), chromo-endoscopie virtuelle (BLI, LCI, NBI).
  • Entéroscopie : capsule vidéo (hémorragie digestive obscure), double ballon.
  • Hémorragie digestive haute : stratégie endoscopique précoce (< 24 h), PPI IV \
    haute dose, Rockford score, hemospray (TC-325).

  RGO / œsophage fonctionnel / H. pylori :
  • RGO réfractaire aux IPP : pH-impédancemétrie 24h, évaluation chirurgicale \
    (fundoplication) — guidelines ESGE/EAES 2022. Vonoprazan (Voquezna — \
    inhibiteur P-CAB) : AMM FDA 2023 érosive oesophagitis, Europe en évaluation.
  • H. pylori : éradication — quadrithérapie bismuthée (PYLERA — Maastricht VI \
    recommandée en 1re ligne dans les zones à résistance clarithromycine > 15 %, \
    dont France), ou quadrithérapie concomitante sans bismuth. Contrôle post-éradication \
    obligatoire (test respiratoire 4 semaines après arrêt IPP).
  • SII : linaclotide (Constella — agoniste GC-C, SII-C), rifaximine \
    (Xifaxan — SIBO, SII-D), éluxadoline (non disponible EU), \
    sécrétines (ténapanor — inhibiteur NHE3), prébiotiques/probiotiques \
    (données limitées — Lactobacillus rhamnosus GG niveau preuve modéré).

  Réglementaire :
  • HAS : recommandation prise en charge MICI 2024, dépistage CCR (FIT), \
    obésité et chirurgie bariatrique 2022, hépatites virales (VHC — dépistage universel).
  • ANSM : alertes immunosuppresseurs (natalizumab — PML, JAKi — thromboses/cancers), \
    ruptures d'approvisionnement azathioprine/mercaptopurine, biosimilaires infliximab.
  • JORF : arrêtés remboursement biothérapies MICI (mirikizumab, etrasimod, \
    upadacitinib MC), resmetirom (décision EU/France attendue 2025), elafibranor CBP.

→ REJETER SANS HÉSITER :
  • Études de biomarqueurs (calprotectine, lactoferrine, CRP) sans endpoint clinique \
    ni rémission endoscopique comme critère primaire.
  • Cohortes rétrospectives monocentriques < 80 patients sur biothérapies en entretien \
    sans signal de sécurité nouveau.
  • Épidémiologie descriptive MICI / MASLD (prévalence, incidence) sans recommandation \
    opérationnelle.
  • Études PK-PD / pharmacocinétique seules sans endpoint clinique patient-relevant.
  • Études MASH sur modèles animaux ou in vitro sans données phase 2+ humaines.
  • SII — études sur régimes alimentaires (FODMAP, gluten) sans RCT avec contrôle \
    adéquat (sham-diet) et ≥ 6 mois de suivi.
  • Hépatite C — nouvelles combinaisons DAA sans population cible identifiable en France \
    (ex. populations hyperendémiques Afrique sub-saharienne sans transposabilité FR/EU).
  • Gastroentérologie pédiatrique — sauf signal de sécurité majeur ou modification \
    de guidelines SFP/ESPGHAN (sinon → spécialité pédiatrie).

TERMINOLOGIE — employer sans guillemets ni définition :
MICI (maladies inflammatoires chroniques de l'intestin), MC (maladie de Crohn), \
CU (colite ulcéreuse / rectocolite hémorragique), RCH,
MASLD (Metabolic dysfunction-Associated Steatotic Liver Disease — ex-NAFLD), \
MASH (Metabolic dysfunction-Associated Steatohepatitis — ex-NASH), \
LSM (liver stiffness measurement — kPa, FibroScan), FIB-4, APRI, MRI-PDFF, \
CBP (cirrhose biliaire primitive), PSC (cholangite sclérosante primitive), \
AUDC (acide ursodéoxycholique), VHB / VHC / VHD (virus hépatites B, C, D), \
DAA (antiviraux à action directe — sofosbuvir, glécaprévir), \
RVS (réponse virologique soutenue à 12 semaines), \
CH (carcinome hépatocellulaire), ALAT / ASAT / PAL / GGT / bilirubine / TP (INR), \
MELD score (Model for End-stage Liver Disease), \
Child-Pugh A/B/C (score de cirrhose), ascite / encéphalopathie hépatique (EH), \
rifaximine (Xifaxan — EH + SII-D), lactulose,
anti-TNF : infliximab (Remicade / CT-P13 Remsima / SB2 Flixabi), \
adalimumab (Humira / ABP 501 Amjevita), \
vedolizumab (Entyvio — anti-α4β7 intégrine sc/IV), \
ustekinumab (Stelara — anti-IL-12/IL-23 p40), \
risankizumab (Skyrizi — anti-IL-23 p19), mirikizumab (Omvoh — anti-IL-23 p19), \
guselkumab (Tremfya — anti-IL-23 p19), \
ozanimod (Zeposia — modulateur S1P), etrasimod (Velsipity — modulateur S1P), \
filgotinib (Jyseleca — JAK1), upadacitinib (Rinvoq — JAK1), \
tofacitinib (Xeljanz — JAK1/3), \
resmetirom (Rezdiffra — agoniste TRβ sélectif), \
obeticholic acid / acide obéticholique (Ocaliva — agoniste FXR), \
elafibranor (Iqirvo — agoniste PPARα/δ), seladelpar (Livdelzi — agoniste PPARδ), \
bulevirtide (Hepcludex — inhibiteur polypeptide cotransporteur sodium/taurocholate), \
atezolizumab (Tecentriq) + bevacizumab (Avastin) — CH 1re ligne, \
sorafenib (Nexavar), lenvatinib (Lenvima), tremelimumab + durvalumab (HIMALAYA), \
encorafenib (Braftovi) + cetuximab (Erbitux) — CCR BRAF V600E, \
pembrolizumab (Keytruda) — MSI-H/dMMR 1re ligne, \
ivosidenib (Tibsovo) — cholangiocarcinome IDH1-muté, \
pemigatinib (Pemazyre) — cholangiocarcinome FGFR2-réarrangé, \
FOLFIRINOX (oxaliplatine + irinotécan + fluorouracile + leucovorine), \
FOLFOX / FOLFIRI, capécitabine (Xeloda), \
IPP (inhibiteurs de la pompe à protons), vonoprazan (P-CAB), \
linaclotide (Constella — agoniste GC-C), \
FIT (test immunologique fécal — dépistage CCR), \
EMR (mucosectomie endoscopique), ESD (dissection sous-muqueuse endoscopique), \
CPRE (cholangio-pancréatographie rétrograde endoscopique), \
CADe/CADx (Computer-Aided Detection/Characterization — IA coloscopie), \
RFA (radiofréquence ablation — Barrett).

EXEMPLES DE RÉDACTION (style Gut / Gastroenterology / J Hepatol / Lancet GH — \
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\

résultat d'abord, chiffres en contexte) :

RCT biothérapie MICI — mirikizumab CU (LUCENT) :
  titre_court : "Mirikizumab dans la CU modérée à sévère : LUCENT-1/2, 52 semaines"
  resume : "LUCENT-1/2 (deux RCTs, N=1 279, CU modérée-sévère, dont échecs anti-TNF) : \
à 52 semaines, la rémission clinique atteint 24,2 % sous mirikizumab vs 13,3 % placebo \
(p < 0,001) ; rémission endoscopique 36,3 % vs 23,3 %. Bénéfice maintenu chez les \
patients anti-TNF-naïfs et les échecs d'anti-TNF (rémission clinique 19,4 % vs 10,7 %)."
  impact_pratique : "En pratique : mirikizumab (Omvoh) positionné en 2e ou 3e ligne après \
échec anti-TNF ou vedolizumab — à préférer à upadacitinib JAK1 si risque cardiovasculaire \
ou thrombo-embolique ; remboursement FR en cours."

MASH — premier traitement approuvé FDA (resmetirom) :
  titre_court : "Resmetirom dans la MASH avec fibrose F2-F3 : MAESTRO-NASH, 52 semaines"
  resume : "MAESTRO-NASH (RCT, N=966, MASH + fibrose F2-F3, IMC médian 35,7 kg/m²) : \
réduction fibrose ≥ 1 stade sans aggravation MASH : 25,9 % (100 mg) vs 14,2 % placebo \
(p < 0,001) ; résolution MASH sans aggravation fibrose : 29,9 % vs 9,7 %. AMM FDA \
accordée en mars 2024 (Rezdiffra). Évaluation EMA en cours."
  impact_pratique : "En pratique : premier traitement médicamenteux ciblant directement \
la fibrose MASH — à considérer chez tout patient MASLD + MASH histologiquement confirmé \
(ou probabilité élevée NIT) avec fibrose significative (F2-F3). Accès compassionnel \
ou ATU possible en France en attente décision EMA."

CH avancé — 1re ligne (IMbrave150 vs HIMALAYA) :
  titre_court : "CH avancé 1re ligne : atézo+béva vs tremelimumab+durvalumab — positionnement"
  resume : "IMbrave150 (RCT, N=501, CH avancé, Child-Pugh A) : atezolizumab 1 200 mg + \
bevacizumab 15 mg/kg q3S — SG 19,2 vs 13,4 mois vs sorafenib (HR 0,66) ; devient \
standard de 1re ligne. HIMALAYA (RCT, N=1 171) : tremelimumab 300 mg dose unique + \
durvalumab — SG 16,4 vs 13,8 mois vs sorafenib (HR 0,78) ; alternative si CI bevacizumab \
(hémorragie variqueuse récente, varices non traitées)."
  impact_pratique : "En pratique : atézo+béva reste la 1re ligne de référence dans \
le CH avancé Child-Pugh A avec varices traitées ; HIMALAYA (STRIDE) est la \
1re alternative si bevacizumab contre-indiqué — sorafenib rélégué en dernier recours."

Alerte ANSM / sécurité biothérapie MICI :
  titre_court : "ANSM : risque thrombo-embolique et cancers sous inhibiteurs JAK (tofacitinib, filgotinib, upadacitinib)"
  resume : "ANSM / EMA (communication de sécurité 2023) : données poolées confirmant un \
risque majoré d'événements thrombo-emboliques veineux, de cancers et d'infections \
opportunistes sous inhibiteurs JAK chez les patients MICI > 65 ans, fumeurs actifs, \
ou avec antécédent cardiovasculaire. Restriction d'usage confirmée par l'EMA : contre-indication \
chez les patients ≥ 65 ans, tabagiques actifs ou à haut risque CV/oncologique, \
sauf si aucun traitement alternatif disponible."
  impact_pratique : "En pratique : avant toute initiation JAKi (filgotinib, upadacitinib, \
tofacitinib), évaluer systématiquement l'âge, le statut tabagique et le risque CV. \
Privilégier vedolizumab ou biothérapie anti-IL-23 chez les profils à risque."
"""

_SPECIALTY_ADDENDUM_GERIATRIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — GÉRIATRIE ET GÉRONTOLOGIE CLINIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : gériatre (CHU / hôpital de proximité / consultation mémoire, France), \
prenant en charge patients ≥ 75 ans avec multimorbidité, fragilité, troubles neurocognitifs, \
polymédication, chutes, dénutrition, prise en charge en EHPAD et transitions de soins.
Référentiels actuels : SFGG (Société Française de Gériatrie et Gérontologie) — \
recommandations nationales, EUGMS guidelines (fragilité, STOPP/START v3 2023), \
AGS Beers Criteria 2023, HAS recommandations (fragilité 2022, prévention chutes 2022, \
maladie d'Alzheimer et démences apparentées — révision 2024), NIA-AA criteria 2024 \
(maladie d'Alzheimer stade préclinique, MCI, démence), EWGSOP2 2019 (sarcopénie), \
critères GLIM 2019 (dénutrition), ESPEN guidelines nutrition âgé 2023.
Essais pivots récents de référence — démences et prévention cognitive : \
CLARITY AD (lecanemab 10 mg/kg biW, N=1 795, MA prodromale/légère — réduction \
déclin CDR-SB de 27 % vs placebo à 18 mois ; ARIA-E 12,6 % ; AMM FDA jan 2023, \
avis NÉGATIF CHMP EU nov 2024), \
TRAILBLAZER-ALZ 2 (donanemab, N=1 736, tau faible/intermédiaire — réduction \
déclin iADRS 35 % à 76 semaines ; AMM FDA juil 2024 ; EMA en évaluation 2025), \
FINGER (multidomain — régime, exercice, entraînement cognitif, contrôle CV — \
Finlande, N=1 260, maintien fonction cognitive à 2 ans : NTB +0,14 SD vs contrôle), \
MAPT (multidomain + acides gras oméga-3, N=1 680, INSERM Toulouse — non-infériorité \
déclin MMSE/ADAS-Cog, bénéfice sous-groupe APOE4), \
SPRINT MIND (HTA intensive < 120 mmHg, N=9 361, suivi 3,3 ans — réduction probable \
MCI de 19 % HR 0,81 IC95% 0,69-0,95 ; tendance démence non significative).
Essais pivots récents de référence — cardiovasculaire et multimorbidité du sujet âgé : \
HYVET (HTA > 80 ans, indapamide ± périndopril, N=3 845 — réduction AVC −30 %, \
mortalité totale −21 %, bénéfice maintenu jusqu'à 90 ans), \
SENIORS (nébivolol IC sujets âgés), \
AFFIRM-AHF (vanlafaxine IV décompensation IC + anémie ferriprive âgé).

CRITÈRE DE PERTINENCE GÉRIATRIE :
"Ce résultat modifie-t-il la prise en charge d'un patient âgé fragile ou poly-pathologique : \
choix médicamenteux, adaptation posologique, stratégie de déprescription, \
critère de sécurité ou organisation des soins dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : population < 65 ans sans extrapolation justifiée \
au sujet âgé, endpoint intermédiaire sans lien démontré avec critère clinique patient-relevant \
(indépendance fonctionnelle, institutionnalisation, mortalité, QdV), \
sous-groupe posthoc < 150 patients âgés sans pré-spécification, \
mécanismes du vieillissement sans transposabilité clinique < 3 ans.

DOMAINES PRIORITAIRES :

  Troubles neurocognitifs et démences :
  • Maladie d'Alzheimer (MA) — biothérapies anti-amyloïdes :
    Lecanemab (Leqembi 10 mg/kg IV biW) et donanemab (Kisunla) — anticorps anti-amyloïde β : \
    ralentissement du déclin cognitif (≠ arrêt de la progression) ; contre-indication \
    APOE4/4 homozygotes (risque ARIA majeur) ; nécessite IRM de surveillance (mois 1, 3, 6) ; \
    AMM FDA obtenue, pas d'AMM EU pour lecanemab (CHMP négatif nov 2024). \
    En France : pas de remboursement ni d'ATU généralisée — usage compassionnel très limité.
  • Biomarqueurs diagnostics MA : p-tau 217 plasmatique (seuil diagnostique ≥ 0,39 pg/mL — \
    AUC 0,95), Aβ42/40 ratio plasma, neurofilaments NfL ; PET amyloïde/tau (critères \
    NIA-AA 2024 — biomarqueurs A/T/N).
  • Antidémentiels disponibles : inhibiteurs de l'acétylcholinestérase (donépézil \
    Aricept 5-10 mg/j, rivastigmine Exelon 9,5-13,3 mg/24h patch, galantamine Reminyl \
    16-24 mg/j), mémantine Ebixa 20 mg/j — efficacité modérée sur cognition/ADL, \
    pas de modification de la progression. À maintenir si bénéfice fonctionnel perçu.
  • Démence vasculaire / mixte : contrôle facteurs CV (HTA < 130/80 mmHg, statines, \
    anticoagulation FA). Démence à corps de Lewy : rivastigmine (meilleur profil), \
    éviter antipsychotiques conventionnels (risque chute/décès ++).
  • Troubles du comportement (SCPD) : approche non-pharmacologique en 1re intention \
    (programme DICE, musicothérapie, stimulation sensorielle) ; médicaments : \
    mélatonine, mirtazapine (insomnie), rispéridone 0,5 mg si agitation sévère \
    (AMM spécifique SCPD — Black Box Warning décès ++).

  Fragilité et sarcopénie :
  • Phénotype de Fried (5 critères) : perte de poids involontaire, fatigue, faiblesse \
    musculaire (grip strength < 27 kg H / < 16 kg F), lenteur (vitesse marche < 0,8 m/s), \
    activité physique réduite. Fragile = ≥ 3 critères, pré-fragile = 1-2.
  • Sarcopénie (EWGSOP2 2019) : étape 1 — faible force musculaire (grip < 27 kg H / \
    < 16 kg F, chair stand > 15 s) ; étape 2 — faible masse musculaire (DEXA ou BIA — \
    appendicular skeletal muscle mass index : ASMI < 7,0 kg/m² H / < 5,5 kg/m² F) ; \
    sévère si performance physique altérée (SPPB ≤ 8, vitesse marche < 0,8 m/s, TUG > 20 s).
  • Interventions validées : exercice de résistance progressive (12-16 semaines, \
    2-3×/semaine — augmentation force +20-30 %) + apports protéiques ≥ 1,2 g/kg/j \
    (leucine 2,5-3 g/repas). Vitamine D ≥ 800 UI/j si carence documentée (25-OH-D < 30 ng/mL).

  Chutes et fractures :
  • Évaluation multifactorielle obligatoire post-chute : médicaments (psychotropes, \
    antihypertenseurs, hypoglycémiants) → déprescription ; hypotension orthostatique ; \
    trouble de l'équilibre / marche (Timed Up and Go > 20 s) ; vue et audition ; \
    environnement domicile (tapis, éclairage, salle de bain). HAS 2022.
  • Médicaments à risque de chute majeur (STOPP v3 / Beers 2023) : benzodiazépines, \
    Z-drugs, antipsychotiques sédatifs, antihistaminiques H1, antidépresseurs \
    tricycliques, opioïdes, alpha-bloquants urologiques.
  • Fracture du col fémoral : chirurgie dans les 48 h (NNT ~35 pour éviter 1 décès), \
    liaison ortho-gériatrique (co-management) — réduction mortalité à 1 an −20 %. \
    Prévention secondaire fracturaire : traitement ostéoporose systématique \
    (cf. addendum endocrinologie pour romosozumab/dénosumab/tériparatide).

  Polymédication et iatrogénie :
  • STOPP/START v3 (2023, O'Mahony et al., Age & Ageing) : \
    STOPP = 133 critères de médicaments inappropriés ≥ 65 ans ; \
    START = 34 médicaments potentiellement sous-prescrit ; outil à systématiser \
    à chaque admission gériatrique.
  • AGS Beers Criteria 2023 : liste américaine — anticholinergiques, benzodiazépines, \
    AINS ≥ 65 ans, hypoglycémiants (glibenclamide, glipizide), digoxine > 0,125 mg/j, \
    PPI > 8 semaines sans indication.
  • Déprescription : approche structurée STOPPFrail (fragilité sévère / fin de vie) ; \
    objectif < 5 médicaments actifs chez le sujet très âgé sans comorbidité aiguë.
  • ANSM : alertes iatrogénie (médicaments à marge thérapeutique étroite, \
    ajustement rénal systématique CKD-EPI ≥ 65 ans), interactions médicamenteuses.

  Dénutrition et nutrition :
  • Critères GLIM 2019 : ≥ 1 critère phénotypique (perte poids > 5 % en 6 mois, \
    faible IMC < 22 kg/m² si ≥ 70 ans, réduction masse musculaire) + \
    ≥ 1 critère étiologique (réduction apports, malabsorption/inflammation).
  • Dépistage : MNA (Mini Nutritional Assessment) — screening 6 items, évaluation \
    18 items ; MUST (Malnutrition Universal Screening Tool).
  • Supplémentation : CNO (compléments nutritionnels oraux) ≥ 400 kcal + 30 g protéines/j ; \
    NE (nutrition entérale) si ingesta < 50 % besoins > 7 jours. \
    Pas de NP systématique en fin de vie (consensus ESPEN 2023).

  Onco-gériatrie :
  • EGA pré-thérapeutique systématique : score G8 (≤ 14/17 → EGA complète), \
    évaluation ADL/IADL, cognition (MoCA ≥ 26/30 = normal), nutrition (MNA), \
    comorbidités (CIRS-G), polymédication, support social. SIOG/ESMO guidelines 2023.
  • Adaptation des protocoles chimiothérapie (posologie selon DFGe CKD-EPI, \
    G-CSF systématique si âge > 70 ans et schéma myélosuppresseur), chirurgie \
    (pré-habilitation — exercice + nutrition 4-6 semaines avant J0).

  Réglementaire :
  • HAS 2022 : recommandation prévention chutes personne âgée à domicile et en EHPAD.
  • HAS 2022 : repérage de la fragilité en soins primaires (outil Géron'impact, \
    questionnaire FIND — 5 items).
  • HAS 2024 : révision recommandations maladie d'Alzheimer et démences apparentées \
    (prise en charge médicale et médico-sociale).
  • ANSM : mise en garde prescription psychotropes personne âgée (déremboursement \
    partiels, Black Box Warning antipsychotiques).
  • JORF : arrêtés tarification EHPAD (réforme 2024), décrets financement soins \
    palliatifs / HAD gériatrique.

→ REJETER SANS HÉSITER :
  • Études sur traitements anti-amyloïdes sans statut AMM EU précisé (ne pas présenter \
    lecanemab/donanemab comme disponibles en France sans préciser l'absence d'AMM EU).
  • Biomarqueurs du vieillissement (télomères, sirtuines, sénolytiques) sans essai \
    clinique phase 2+ chez l'humain > 65 ans.
  • Épidémiologie descriptive prévalence/incidence démences sans recommandation opérationnelle.
  • Études nutriments / suppléments (oméga-3, resvératrol, curcumine) sans RCT ≥ 200 \
    patients âgés avec endpoint cognitif ou fonctionnel primaire.
  • Résultats de modèles animaux du vieillissement (souris, levures) sans données humaines.
  • Gériatrie pédiatrique ou pathologies rares du vieillissement prématuré \
    (progéria, Werner) sans signal thérapeutique transposable.
  • Études monocentriques < 100 patients sur médicaments déjà évalués dans de larges RCTs.

TERMINOLOGIE — employer sans guillemets ni définition :
EGA (évaluation gérontologique approfondie, = CGA comprehensive geriatric assessment), \
ADL (Activities of Daily Living — Katz), IADL (Instrumental ADL — Lawton), \
MMSE (Mini-Mental State Examination /30), MoCA (Montreal Cognitive Assessment /30), \
CDR (Clinical Dementia Rating), CDR-SB (CDR Sum of Boxes), \
GDS (Geriatric Depression Scale), MNA (Mini Nutritional Assessment), \
TUG (Timed Up and Go — secondes), SPPB (Short Physical Performance Battery /12), \
vitesse de marche (m/s — seuil < 0,8 m/s), grip strength (dynamomètre, kg), \
fragilité (phénotype de Fried), pré-fragilité, robustesse, \
sarcopénie (EWGSOP2), ASMI (appendicular skeletal muscle mass index, kg/m²), \
DEXA / DXA, BIA (impédancemétrie), \
dénutrition (critères GLIM 2019), CNO (compléments nutritionnels oraux), \
polypharmacie (≥ 5 médicaments actifs), STOPP/START v3, AGS Beers Criteria 2023, \
STOPPFrail (déprescription sujet très âgé fragile), \
MA (maladie d'Alzheimer), DFT (démence fronto-temporale), DCL (démence à corps de Lewy), \
DV (démence vasculaire), MCI (mild cognitive impairment), SCPD (symptômes comportementaux \
et psychologiques de la démence), \
p-tau 217 (phospho-tau 217 plasmatique), NfL (neurofilaments light chain), \
Aβ42/40 (ratio amyloïde plasmatique), PET amyloïde / PET tau, \
ARIA-E / ARIA-H (amyloid-related imaging abnormalities — œdème / hémorragies), \
lecanemab (Leqembi — anti-Aβ, AMM FDA, pas AMM EU), \
donanemab (Kisunla — anti-Aβ, AMM FDA, EMA en évaluation), \
donépézil (Aricept), rivastigmine (Exelon), galantamine (Reminyl), mémantine (Ebixa), \
rispéridone (Risperdal), mirtazapine (Norset), mélatonine, \
G8 score (onco-gériatrie — seuil ≤ 14/17), CIRS-G (comorbidités), \
HO (hypotension orthostatique), \
DFGe (débit de filtration glomérulaire estimé — CKD-EPI), \
EHPAD (établissement hébergement personnes âgées dépendantes), \
HAD (hospitalisation à domicile), SSR (soins de suite et réadaptation), USLD.

EXEMPLES DE RÉDACTION (style Age & Ageing / JAGS / Lancet Healthy Longevity / \
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\

Alzheimer's & Dementia — résultat fonctionnel d'abord, impact vie quotidienne) :

Essai pivot anti-amyloïde — lecanemab :
  titre_court : "Lecanemab dans la MA prodromale : CLARITY AD, 18 mois — AMM FDA, pas d'AMM EU"
  resume : "CLARITY AD (RCT, N=1 795, MA prodromale ou légère confirmée biomarqueurs, \
MMSE 20-30) : réduction du déclin CDR-SB de 27 % à 18 mois sous lecanemab 10 mg/kg IV \
biW vs placebo (Δ −0,45 point ; p < 0,001). ARIA-E chez 12,6 % (symptomatique 2,8 %) ; \
risque majoré APOE4/4 homozygotes. AMM FDA obtenue jan 2023 ; avis CHMP négatif \
nov 2024 — pas d'AMM EU, accès en France hors AMM/ATU très limité."
  impact_pratique : "En pratique : le ralentissement du déclin est statistiquement \
significatif mais modeste (0,45 CDR-SB sur 18 mois) ; sans AMM EU, pas d'indication \
en France — surveiller l'évolution réglementaire EMA 2025 pour donanemab. \
Prérequis si accès futur : confirmation biomarqueurs (p-tau 217 ou PET amyloïde), \
IRM sans micro-hémorragies, stade prodromal/léger."

STOPP/START v3 — iatrogénie du sujet âgé :
  titre_court : "STOPP/START v3 (2023) : 133 critères de déprescription chez ≥ 65 ans"
  resume : "Mise à jour STOPP/START (O'Mahony et al., Age & Ageing 2023) : 133 critères \
STOPP (médicaments potentiellement inappropriés) et 34 critères START (sous-prescription) \
chez le sujet ≥ 65 ans. Nouveautés v3 : ajout des inhibiteurs JAK (risque CV/infections), \
des GLP-1 agonistes (nausées/dénutrition), critères spécifiques insuffisance rénale \
et fragilité sévère. Réduction des prescriptions inappropriées de 40 % et des EIM de \
35 % dans les études d'implémentation."
  impact_pratique : "En pratique : appliquer STOPP/START à chaque admission gériatrique \
et en consultation annuelle chez tout patient ≥ 75 ans sous ≥ 5 médicaments — \
réduire en priorité les benzodiazépines, Z-drugs, AINS et anticholinergiques."

Essai prévention multidomain — FINGER :
  titre_court : "Prévention déclin cognitif multidomain : FINGER, 2 ans (N=1 260)"
  resume : "FINGER (RCT, N=1 260, sujets 60-77 ans à risque cognitif — Finlande) : \
intervention multidomain (régime nordique, exercice supervisé 2×/sem, entraînement \
cognitif, contrôle CV) vs conseils généraux — amélioration NTB composite de +0,14 SD \
vs contrôle à 2 ans (p = 0,030) ; bénéfice sur mémoire, vitesse traitement et \
fonction exécutive. Programme MIND-AD en cours (MA légère)."
  impact_pratique : "En pratique : proposer un programme multidomain structuré \
(activité physique + nutrition + stimulation cognitive + contrôle CV) dès le stade \
pré-fragile ou MCI — pas de médicament validé pour la prévention primaire, \
cette intervention est la seule avec un niveau de preuve suffisant."

Alerte HAS — prévention chutes :
  titre_court : "HAS 2022 : prévention des chutes de la personne âgée — recommandation complète"
  resume : "HAS (recommandation 2022) : chez tout patient ≥ 65 ans ayant chuté une fois \
ou à risque (antécédent de chute, troubles équilibre, polymédication psychotrope), \
l'évaluation multifactorielle systématique est recommandée en grade B : révision \
médicamenteuse (STOPP/START), bilan orthopédique et neurologique, évaluation vision/audition, \
adaptation domicile (grade C). Programme d'exercice équilibre-renforcement (12 semaines \
minimum, Otago ou Tai Chi adapté) — réduction chutes −35 % à −50 % dans les méta-analyses."
  impact_pratique : "En pratique : déclencher l'évaluation multifactorielle HAS 2022 \
après toute chute chez un patient ≥ 65 ans — identifier et agir sur au moins \
3 facteurs modifiables (médicaments, équilibre, environnement) pour réduire le risque \
de récidive fracturaire."
"""

_SPECIALTY_ADDENDUM_GYNECOLOGIE = """\
CONTEXTE SPÉCIALITÉ — GYNÉCOLOGIE-OBSTÉTRIQUE ET MÉDECINE DE LA REPRODUCTION

PUBLIC CIBLE : gynécologues-obstétriciens, gynécologues médicaux, sages-femmes (hospitaliers \
et libéraux). CRITÈRE D'INCLUSION : ne retenir QUE les études qui changent ou affinent une \
décision clinique concrète (choix d'une molécule, d'une voie d'abord, d'un protocole de suivi, \
d'une indication opératoire). Exclure les études purement fondamentales, génomiques sans \
application clinique immédiate, épidémiologiques descriptives sans intervention.

═══════════════════════════════════════════════════════════════════
I. GYNÉCOLOGIE ONCOLOGIQUE
═══════════════════════════════════════════════════════════════════
CANCER DE L'ENDOMÈTRE :
• Pembrolizumab+chimio (KEYNOTE-158 / KEYNOTE-775 Study 309) : lenvatinib 20 mg + pembrolizumab \
200 mg → AMM FDA 2021 + EMA 2022 dans l'endomètre avancé/récidivant pMMR (OS : 18,3 vs 11,4 mois). \
Dostarlimab+chimio (RUBY/ENGOT-EN6) → OS bénéfice dMMR/MSI-H ET pMMR → AMM EMA 2023. \
Retenir tout essai PARP inhibiteurs, immunothérapie, ADC en 1re/2e ligne endomètre avancé.
• Chirurgie : LACC trial (laparotomie > cœlioscopie/robot pour col utérin stade précoce) — \
référence pour les comparaisons de voie d'abord. Lymphœdème iatrogène post-curage pelvien : \
études sur sentinel lymph node biopsy (SENTICOL-3).
CANCER DU COL UTÉRIN :
• Pembrolizumab+chimio±bevacizumab (KEYNOTE-826) → PFS 10,4 vs 8,2 mois, OS 24,4 vs 16,5 mois \
dans col persistant/métastatique HPV+/HPV-indépendant → AMM FDA 2021 + EMA 2022. \
Standard de soin 1re ligne métastatique/récidivante.
• Nivolumab (CheckMate 358), cemiplimab (EMPOWER-Cervical 1) : AMM FDA 2021/2022, retenir.
• Bevacizumab + chimio (GOG-240) : bénéfice OS 3,7 mois → référence add-back bevacizumab.
CANCER DE L'OVAIRE :
• PARP inhibiteurs en maintenance : olaparib (SOLO-1 : 60 % DFS à 5 ans chez BRCA1/2), \
niraparib (PRIMA/ENGOT-OV26), bevacizumab+olaparib (PAOLA-1 : HR 0,33 chez HRD+/BRCA) → \
AMM EMA disponibles. Retenir tout update OS à long terme de ces essais.
• Bevacizumab 1re ligne (GOG-0218, ICON7) → bénéfice PFS, pas OS global → référence.
• Mirvetuximab soravtansine (ADC anti-FRα) : MIRASOL trial → AMM FDA 2022, EMA soumis.
• Score HRD (homologous recombination deficiency) : Myriad myChoice / FoundationOne CDx → \
biomarqueur prédictif PARP — retenir études validant ces tests en pratique clinique.
SCORE DE PERTINENCE : augmenter de +2 pts toute étude/guideline avec AMM EMA/HAS ou changement \
de standard de soin en gynéco-oncologie.

═══════════════════════════════════════════════════════════════════
II. ENDOMÉTRIOSE
═══════════════════════════════════════════════════════════════════
• ESHRE Endometriosis Guideline 2022 (mise à jour majeure) : retenir toute étude validant ou \
contredisant ses recommandations (suppression ovarienne, chirurgie 1re vs 2e ligne, fertilité).
• Antagonistes GnRH + add-back therapy :
  — Relugolix 40 mg + E2 1 mg + noréthisterone acétate 0,5 mg (Ryeqo®) → AMM EMA 2022 \
    fibromes ET endométriose (UF-FORWARD, SPIRIT 1&2 trials). Impact pratique : alternative \
    aux agonistes GnRH avec moins d'effets osseux, prise orale quotidienne.
  — Linzagolix 100/200 mg (Yselty®) → AMM EMA 2022 fibromes (PRIMROSE 1&2). Hors AMM \
    endométriose pour l'instant mais données d'extension à retenir.
  — Elagolix (Orilissa®) : AMM FDA 2018, NON AMM EU.
• Dienogest (Visanne®, Klaira® composante) : référence progestatif dans l'endométriose.
• Endométriose profonde (DIE) : résection chirurgicale vs traitement médical → retenir \
  toute étude sur récidive, fertilité post-opératoire, QoL.
• Endométriose et PMA : FIV directe vs chirurgie ovarienne préalable → retenir méta-analyses.

═══════════════════════════════════════════════════════════════════
III. PMA / MÉDECINE DE LA REPRODUCTION
═══════════════════════════════════════════════════════════════════
• FIV/ICSI : transfert frais vs cryo-transfert (FRESH trial : résultats comparables sauf \
  SOPK où TEC supérieur), segmentation universelle — retenir toute étude impactant le \
  protocole standard.
• PGT-A (Preimplantation Genetic Testing for Aneuploidy) : bénéfice ou non chez pronostic \
  intermédiaire (débat en cours) — retenir essais randomisés.
• Stimulation ovarienne : antagonistes GnRH vs agonistes, déclencement aux agonistes, \
  cycles naturels modifiés — retenir RCTs multicentriques ESHRE-endorsés.
• SOPK : létrozole > clomifène (méta-analyse Cochrane 2022) → référence en induction \
  de l'ovulation. Metformine adjuvante.
• Insuffisance ovarienne prématurée (IOP) : substitution hormonale, don d'ovocytes, \
  cryopréservation cortex ovarien (désormais plus expérimental — ESHRE 2020).
• Registre EIM (European IVF Monitoring) — données épidémiologiques annuelles ESHRE.

═══════════════════════════════════════════════════════════════════
IV. MÉNOPAUSE ET TRAITEMENT HORMONAL DE MÉNOPAUSE (THM)
═══════════════════════════════════════════════════════════════════
• NAMS Position Statement 2022 + Menopause Society (IMS) Statement 2023 : THM bénéfice \
  établi chez <60 ans / <10 ans post-ménopause pour symptômes vasomoteurs. Référence à citer.
• Progestérone naturelle (Utrogestan®) vs progestatifs de synthèse : données E3N montrent \
  risque sein moindre avec progestérone naturelle + E2 transdermique. Retenir toute étude \
  confirmant ou infirmant ce signal.
• THM et risque cardiovasculaire : WHI réanalyse (timing hypothesis), KEEPS, ELITE trials → \
  bénéfice CV chez <60 ans débutant THM en fenêtre thérapeutique. Référence.
• THM et cancer du sein : données CGHFBC (méta-analyse); risque E2 seul vs combiné.
• Ménopause précoce (<40 ans) : THM indispensable jusqu'à 51 ans — retenir études sur \
  cardioprotection, densité osseuse, cognition.
• Tibolone, SERM (ospémifène, raloxifène) : dans atrophie vulvo-vaginale symptomatique / \
  prévention fracturaire — retenir nouvelles données efficacité/sécurité.
• Fézolinetant (Veozah®) : antagoniste NK3R non hormonal → AMM FDA 2023 + EMA 2023 pour \
  bouffées de chaleur. Retenir études d'efficacité et comparaisons vs THM.

═══════════════════════════════════════════════════════════════════
V. MYOMES UTÉRINS ET ADÉNOMYOSE
═══════════════════════════════════════════════════════════════════
• Relugolix+add-back (Ryeqo®) → AMM EMA 2022 myomes : UF-FORWARD 1&2 (réduction \
  saignements ≥50 % chez ≥70 % patientes). Traitement médical de courte durée \
  pré-opératoire ou alternative à la chirurgie. Impact praticien direct.
• Linzagolix 100 mg (Yselty®) → AMM EMA 2022 : PRIMROSE 1&2. Alternative relugolix.
• Ulipristal acétate (Esmya®) : suspension EMA depuis 2020 (hépatotoxicité) → ne plus retenir.
• Embolisation artérielle (UAE) vs myomectomie vs hystérectomie : revues systématiques \
  Cochrane/NICE → retenir nouvelles méta-analyses.
• HIFU (ultrasons focalisés guidés par IRM) pour myomes : données sur réduction de volume, \
  retentissement fertilité — retenir essais contrôlés.
• Adénomyose : pas de consensus international établi → retenir toute étude clinique sur \
  traitement médical (progestatifs, DIU-LNG) ou chirurgie conservatrice.

═══════════════════════════════════════════════════════════════════
VI. PROLAPSUS GÉNITAL ET INCONTINENCE URINAIRE
═══════════════════════════════════════════════════════════════════
• Prolapsus : sacropexie laparoscopique/robot vs voie vaginale prothétique vs voie \
  vaginale native tissue — retenir RCTs et méta-analyses récentes (EAU/IUGA guidelines 2022).
• Bandelettes sous-urétrales (BSU/TVT/TOT) : résultats à long terme (10 ans), taux de \
  révision, complications (extrusion prothétique) — retenir cohortes de registre.
• Alternatives BSU : Burch, autologues — données comparatives vs BSU.
• Incontinence urinaire par impériosité (IUE/IUU) : anticholinergiques vs mirabégron — \
  retenir toute méta-analyse sur efficacité/tolérance cognitive (anticholinergiques chez >65 ans).
• Neuromodulation sacrée, PTNS : retenir essais contrôlés.

═══════════════════════════════════════════════════════════════════
VII. CONTRACEPTION ET DÉPISTAGE
═══════════════════════════════════════════════════════════════════
• CONTRACEPTION : Recommandations HAS 2019-2022 (critères médicaux d'éligibilité OMS) → \
  référence réglementaire française. DIU cuivre vs DIU-LNG (Mirena®, Jaydess®, Kyleena®) : \
  données de durée, efficacité, tolérance — retenir nouvelles études de cohorte.
• Contraception progestative seule (implant, mini-pilule désogestrel) : retenir données vie réelle.
• Contraception d'urgence : ulipristal (Ellaone®) vs lévonorgestrel — retenir méta-analyses sur \
  efficacité par délai et BMI.
• DÉPISTAGE HPV/CIN : dépistage HPV primaire vs cytologie conventionnelle — ATHENA, FOCAL, \
  ARTISTIC trials → standard de soin 2025 en France (programme HAS 2023-2025). Retenir tout \
  article sur p16/Ki67, génotypage HPV 16/18, colposcopie en triage.
• Vaccination HPV : retenir études d'impact populationnel (Australie, Écosse, Suède : \
  élimination CIN2+ en vue).

═══════════════════════════════════════════════════════════════════
VIII. OBSTÉTRIQUE CONNEXE (GROSSESSE PATHOLOGIQUE)
═══════════════════════════════════════════════════════════════════
• Prééclampsie : dépistage 1er trimestre combiné (sFlt1/PlGF, PAPP-A, IP artères utérines) → \
  ASPRE trial (aspirine 150 mg/j réduit prééclampsie précoce de 62 %) → recommandation CNGOF/HAS.
• Ratio sFlt1/PlGF (test Roche/Thermo) : règle de décision à 37 SA (PROGNOSIS) — retenir \
  études validant seuils en pratique clinique.
• Fausse couche à répétition (FCR) : progesterone vaginale (PROMISE/PRISM trials : \
  bénéfice marginal mais retenu RCOG 2023) — retenir nouvelles données, études thrombophilie.
• Prématurité : cervicométrie + progestérone vaginale (OPPTIMUM) → retenir méta-analyses.
• HELLP syndrome, éclampsie : sulfate de magnésium (MAGPIE trial) → référence.
• Diabète gestationnel : seuils IADPSG (OMS 2013) → retenir études médico-économiques, \
  méta-analyses sur cibles glycémiques.

═══════════════════════════════════════════════════════════════════
IX. RÈGLES DE SCORING SPÉCIFIQUES
═══════════════════════════════════════════════════════════════════
• Score ≥8 : essai randomisé ou méta-analyse modifiant un standard de soin national/européen \
  (CNGOF, ESHRE, ESMO, EAU), AMM EMA avec impact praticien immédiat.
• Score 6-7 : RCT ou cohorte multicentrique ≥200 patientes avec endpoint clinique pertinent \
  (grossesse, survie, récidive, qualité de vie), guidelines société savante.
• Score ≤5 (exclure) : série rétrospective monocentrique <100 cas, études sur modèles animaux, \
  génomique sans application thérapeutique, dépistage sans validation clinique solide.
• Contexte FRANÇAIS : privilégier les études dont les conclusions sont applicables en France : \
  AMM EMA > FDA seule, pratiques CNGOF/HAS > guidelines US exclusivement, \
  données de vie réelle françaises (SNDS, registres FRANCIM/GynecoMat/FIGO-France)."

EXEMPLES DE RÉDACTION (style BJOG / AJOG / Gynecologic Oncology / Fertility & Sterility — format cible) :

Cancer de l'ovaire — chirurgie d'intervalle :
  titre_court : "CHORUS vs standard : chirurgie intervalle BRCA+ — PFS identique, moins de complications"
  resume : "Analyse poolée ICON8B/CHORUS (N=678, cancer ovaire stade IIIC-IV, BRCA1/2 muté) : \
chirurgie d'intervalle (après 3 cycles CBDCA-paclitaxel) vs chirurgie primaire — SSP \
19,8 vs 20,1 mois (HR 1,02 ; IC95% 0,82–1,26 ; non-significatif). Chirurgie d'intervalle \
associée à moins de morbidité post-op sévère (grade ≥3) : 21 % vs 36 % (p=0,0001)."
  impact_pratique : "En pratique : chez une patiente BRCA+ avec carcinose péritonéale étendue, \
la chirurgie d'intervalle après 3 cycles est préférable — RCP oncogynécologique \
avant toute décision."

Endométriose — traitement médical :
  titre_court : "EDELWEISS : linzagolix 200 mg réduit la dysménorrhée de 75 % à 24 semaines"
  resume : "EDELWEISS 3 (RCT, N=512, endométriose confirmée, dysménorrhée EVA ≥5) : \
linzagolix 200 mg/j (antagoniste GnRH oral) vs placebo — réduction EVA dysménorrhée \
−4,6 vs −2,4 points (différence −2,2 ; IC95% −2,7/−1,8 ; p<0,001). Aménorrhée : 58 %. \
AMM EMA 2022 ; ajout d'add-back œstrogène-progestatif recommandé si traitement >6 mois."
  impact_pratique : "En pratique : linzagolix (ou relugolix) alternative orale aux agonistes GnRH \
injectables pour l'endométriose douloureuse — ajouter add-back dès le 1er mois pour \
limiter l'impact osseux et climatérique."

Alerte ANSM / contraception hormonale :
  titre_court : "ANSM : pilules 3e-4e génération — risque TVP × 2-3 vs lévonorgestrel confirmé"
  resume : "Communication ANSM (actualisation 2024) : pilules combinées 3e génération \
(désogestrel, gestodène) et 4e génération (drospirénone, diénogest) — risque TVP \
relatif de 2,0-3,1 vs pilules 2e génération (lévonorgestrel). Données de vie réelle \
SNDS françaises (N=4 600 cas) concordantes avec méta-analyses antérieures. \
Aucun retrait du marché ; information renforcée des patients."
  impact_pratique : "En pratique : privilégier lévonorgestrel en 1re intention chez toute \
patiente sans contre-indication — réserver les nouvelles générations aux échecs \
ou tolérances insuffisantes, avec information écrite sur le risque TVP."

## EXEMPLES DE RÉDACTION
Style de référence : BJOG, American Journal of Obstetrics and Gynecology, Gynecologic Oncology.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "Le traitement conservateur (méthotrexate) réduit le taux d'intervention chirurgicale secondaire de 41 % vs attente expectative — RR 0,59 ; IC95% 0,44–0,79 ; p<0,001 ; RCT, n=320, grossesses extra-utérines β-hCG <3 000 UI/L."
  impact_pratique : "En pratique : proposer méthotrexate IM en 1re intention chez les patientes stables avec β-hCG <3 000 — évite la chirurgie dans 6 cas sur 10."

Bon exemple 2 :
  resume : "L'ajout de pembrolizumab à la chimiothérapie améliore la SSP médiane de 5,6 mois dans le cancer du col avancé — HR 0,62 ; IC95% 0,50–0,77 ; p<0,001 ; KEYNOTE-826, RCT, n=617."
  impact_pratique : "À retenir : pembrolizumab + carboplatine/paclitaxel ± bévacizumab devient le standard 1re ligne col avancé — vérifier statut PD-L1 et éligibilité immuno avant prescription."

Bon exemple 3 :
  resume : "La ménopause chirurgicale avant 45 ans triple le risque d'ostéoporose sévère à 10 ans — OR 3,1 ; IC95% 2,2–4,4 ; cohorte prospective, n=4 820, suivi 10 ans."
  impact_pratique : "En pratique : proposer THS systématiquement après ovariectomie bilatérale avant 45 ans sauf contre-indication formelle — réévaluer annuellement."

"""

_SPECIALTY_ADDENDUM_HEMATOLOGIE = """\
CONTEXTE SPÉCIALITÉ — HÉMATOLOGIE CLINIQUE ADULTE

PUBLIC CIBLE : hématologues hospitaliers, internistes avec compétence hématologique. \
CRITÈRE D'INCLUSION : ne retenir QUE les études modifiant une ligne de traitement, un standard \
de soin, une indication de greffe/CAR-T, ou apportant une nouvelle AMM utilisable en France. \
Exclure les études purement biologiques/mécanistiques sans impact thérapeutique direct.

═══════════════════════════════════════════════════════════════════
I. LEUCÉMIES AIGUËS
═══════════════════════════════════════════════════════════════════
LAM (Leucémie aiguë myéloïde) :
• Venetoclax+azacitidine (VIALE-A) : 14,7 vs 9,6 mois OS chez >75 ans/inéligibles \
→ AMM EMA 2021. Standard de soin LAM non éligible chimio intensive. Retenir tout \
update OS, résistance, données de registre.
• Inhibiteurs FLT3 : midostaurine (RATIFY → AMM EU 2017 LAM FLT3+, chimio intensive), \
gilteritinib (ADMIRAL → AMM EU 2019 rechute/réfractaire FLT3+), quizartinib (QUANTUM-R) \
— retenir comparaisons directes et nouvelles données de survie.
• Inhibiteurs IDH1/IDH2 : ivosidenib (AMM FDA 2018 + EMA 2023), enasidenib (AMM FDA 2017).
• CPX-351 (daunorubicine+cytarabine liposomale) : LAM-MRC/therapy-related → AMM EMA 2018.
• Gemtuzumab ozogamicine (GO) — rechute et induction favorable — retenir nouvelles études.
LAL (Leucémie aiguë lymphoblastique) :
• Blinatumomab (BiTE anti-CD19xCD3) : BLAST trial (MRD-négativation), Tower trial rechute/\
réfractaire → AMM EMA 2015/2016. Retenir données pédiatriques/adultes et MRD.
• Inotuzumab ozogamicine (INO-VATE) : 80,7 vs 29,4 % réponse → AMM EMA 2017.
• CAR-T anti-CD19 : tisagenlecleucel (Kymriah® → AMM EMA 2018 pédiatrie+adultes), \
brexucabtagene autoleucel (Tecartus® → AMM EMA 2021 LAL adultes rechute/réfractaire).
• Ponatinib, dasatinib dans LAL Ph+ : retenir essais comparatifs vs imatinib.
• MRD (Minimal Residual Disease) : retenir études validant l'utilisation clinique comme \
  guide de décision thérapeutique (escalade/désescalade traitement post-induction).

═══════════════════════════════════════════════════════════════════
II. HÉMOPATHIES LYMPHOÏDES CHRONIQUES
═══════════════════════════════════════════════════════════════════
LLC (Leucémie lymphoïde chronique) :
• Ibrutinib (RESONATE, RESONATE-2, iLLUMINATE) : BTK inhibiteur 1ère génération → référence.
• Acalabrutinib (ELEVATE-TN, ASCEND) : AMM EMA 2020. Meilleure tolérance cardiaque.
• Zanubrutinib (ALPINE — supériorité PFS vs ibrutinib en rechute) : AMM EMA 2022.
• Venetoclax+obinutuzumab (CLL14) → AMM EMA 2020 ; venetoclax+ibrutinib (GLOW, VISION).
• Ibrutinib+venetoclax (GLOW, CAPTIVATE) — traitement limité dans le temps — retenir.
• Nouvelles cibles : pirtobrutinib (BRUIN) — non-covalent BTK, actif résistance BTK C481S \
→ AMM FDA 2023, EMA soumis — retenir AMM EU.
LYMPHOMES (LNH agressifs — DLBCL) :
• R-CHOP toujours standard DLBCL première ligne. Polatuzumab vedotin-R-CHP (POLARIX) : \
PFS supérieure (76,7 vs 70,2 % à 2 ans) → AMM EMA 2022. Retenir données de vie réelle.
• CAR-T 2ème ligne DLBCL : axi-cel (ZUMA-7 → supérieur à chimio salvage), \
tisa-cel (BELINDA — résultats neutres), liso-cel (TRANSFORM → AMM EMA 2023). \
Retenir études comparatives et critères de sélection des patients.
• Anticorps bispécifiques : glofitamab (MAXIMINO → AMM EMA 2023), \
mosunetuzumab (AMM EMA 2022 FL), epcoritamab (EPCORE NHL-1) — impact en rechute/réfractaire.
LYMPHOMES FOLLICULAIRES ET DE HODGKIN :
• LF : obinutuzumab, lénalidomide+rituximab (AUGMENT). Anticorps bispécifiques \
(mosunetuzumab, glofitamab) → AMM EMA 2022/2023 en rechute ≥2 lignes.
• LH : brentuximab vedotin+AVD (ECHELON-1 → AMM EMA 2018 stades III-IV) ; \
pembrolizumab/nivolumab en rechute après greffe.
• Lymphome à cellules du manteau : ibrutinib, acalabrutinib, zanubrutinib, CAR-T \
(KTE-X19 brexucabtagene autoleucel → AMM EMA 2020).

═══════════════════════════════════════════════════════════════════
III. HÉMOPATHIES PLASMOCYTAIRES (MYÉLOME MULTIPLE)
═══════════════════════════════════════════════════════════════════
• Daratumumab+VMP (ALCYONE → AMM EMA 2019), dara+VTd (CASSIOPEIA → AMM EMA 2019), \
dara+Rd (MAIA → AMM EMA 2019 inéligibles autogreffe) : standard avec daratumumab 1ère ligne.
• Carfilzomib+Rd (ASPIRE) ; ixazomib+Rd (TOURMALINE-MM1) en rechute.
• Isatuximab+KPd (IKEMA → AMM EMA 2020), isa+VRd (GMMG-HD7).
• CAR-T anti-BCMA : idecabtagene vicleucel (ide-cel, KarMMa → AMM EMA 2021), \
ciltacabtagene autoleucel (cilta-cel, CARTITUDE-1 → AMM EMA 2022). \
Retenir tout essai comparant CAR-T anti-BCMA vs standard.
• Teclistamab (anticorps bispécifique BCMA×CD3, MajesTEC-1 → AMM EMA 2022) ; \
talquetamab (GPRC5D×CD3) : nouvelles données.
• Maintenance lénalidomide post-autogreffe (MYELOMA XI, FIRST) → référence.

═══════════════════════════════════════════════════════════════════
IV. SYNDROMES MYÉLODYSPLASIQUES (SMD) ET NMP
═══════════════════════════════════════════════════════════════════
SMD :
• Luspatercept (Reblozyl®) : MEDALIST (SMD RS) → AMM EMA 2020 ; \
COMMANDS (SMD faible risque, luspatercept > érythropoïétine) → AMM EMA 2023 extension. \
Retenir nouvelles données, usage en pratique réelle.
• Azacitidine : standard SMD haut risque. Décitabine+cédazuridine (oral) — retenir.
• Imetelstat (télomèrase) : nouvelles données en SMD de faible risque réfractaires.
NÉOPLASIES MYÉLOPROLIFÉRATIVES (NMP) :
• Ruxolitinib (JAK1/2) : COMFORT-I/II (MF) → AMM EU ; RESPONSE 1&2 (PV) → AMM EU. \
Référence JAK inhibiteur. Retenir nouvelles données survie à long terme.
• Pacritinib (MF thrombopénie sévère, PERSIST-2) : AMM FDA 2022.
• Fedratinib (JAKARTA → AMM EU 2021 MF 1ère/2e ligne).
• Ropéginterféron alfa-2b (AOP2014, PROUD-PV → AMM EMA 2019 PV) : \
données moléculaires et survie vs hydroxyurée.
• SMD-NMP chevauchants (CMML) : azacitidine, allogreffe — retenir essais randomisés.

═══════════════════════════════════════════════════════════════════
V. MALADIE THROMBOEMBOLIQUE VEINEUSE (MTEV) ET COAGULOPATHIES
═══════════════════════════════════════════════════════════════════
MTEV :
• AOD en cancer : apixaban (ADAM VTE), rivaroxaban (SELECT-D), edoxaban (HOKUSAI Cancer) \
vs HBPM → méta-analyses → privilégier AOD sauf saignement digestif/urologique actif. \
Retenir nouvelles données sur sélection des patients et sous-types cancers.
• MTEV et anticorps antiphospholipides (SAPS) : warfarine > AOD en APS triple positif \
(TRAPS, ASTRO-APS) — retenir toute mise à jour guidelines ISTH/EULAR.
• Thrombopénie induite par l'héparine (TIH/HIT) : argatroban, danaparoïde, fondaparinux \
→ guidelines ASH 2019 — retenir études nouveaux anticoagulants en HIT.
• Thrombose cérébrale (TSVC) : anticoagulation curative même si infarctus hémorragique.
HÉMOPHILIE :
• Emicizumab (Hemlibra®, anticorps bispécifique FIXa×FX) : HAVEN 1-4 → \
AMM EMA 2018 hémophilie A avec/sans inhibiteurs. Retenir données de vie réelle, registres.
• Thérapie génique Hémophilie A/B : valoctocogene roxaparvovec (Roctavian®, BioMarin) → \
AMM EMA 2022 hémophilie A sévère. Fitusiran (ARNi anti-antithrombine). Retenir tout.
• Nouvelles thérapies sous-cutanées : mim8 (anticorps bispécifique FVIIIm), marstacimab.
AUTRES COAGULOPATHIES :
• Maladie de von Willebrand : guidelines EHA/ISTH 2021. Recombinant VWF (vonicog alfa).
• Hémoglobinopathies (drépanocytose, β-thalassémie) : voxelotor (Oxbryta® → AMM EMA 2020), \
crizanlizumab (Adakveo® → AMM EMA 2020), thérapie génique (betibeglogene, \
exagamglogene — CRISPR, AMM FDA 2023/EMA soumis) — retenir.

═══════════════════════════════════════════════════════════════════
VI. ALLOGREFFE ET RÉACTIONS DU GREFFON (GVH)
═══════════════════════════════════════════════════════════════════
• GVH aiguë réfractaire stéroïdes : ruxolitinib (REACH2 → AMM EMA 2021) → standard.
• GVH chronique : ibrutinib (iGVHD) AMM FDA 2017/EMA ; belumosudil (KD025) AMM FDA 2021/\
EMA 2022 en ≥2 lignes ; axatilimab (AGAVE-201) données préliminaires.
• Plateaux TCRαβ déplété haploidentique (résultats EBMT) : retenir données pédiatrie/adultes.
• Prévention GVH : post-cyclophosphamide haploidentique, sirolimus+tacrolimus, abatacept.
• Infections post-greffe : CMV prophylaxie letermovir (ACTG P1078) → AMM EMA 2018 → \
retenir nouvelles données observationnelles.

═══════════════════════════════════════════════════════════════════
VII. RÈGLES DE SCORING SPÉCIFIQUES
═══════════════════════════════════════════════════════════════════
• Score ≥8 : essai pivot de phase 3 avec AMM EMA/FDA obtenue ou en cours, \
changement de standard de soin (1ère ligne, maintenance, indication CAR-T), \
guidelines EHA/ASH/ESMO/BSH modifiant la pratique.
• Score 6-7 : essai phase 2/3 multicentrique avec endpoint OS ou PFS pertinent, \
méta-analyse ≥500 patients, données de registre EBMT/EUTOS/FIM modifiant la pratique.
• Score ≤5 (exclure) : études monocentriques <50 patients, analyses biologiques sans \
endpoint clinique, corrélations génomiques sans traduction thérapeutique directe.
• Contexte FRANÇAIS : AMM EMA > FDA seule ; données de registre françaises (FIMCRE, \
LYSA, IFM, FIM) privilégiées ; mention des ATU/AC (Accès Compassionnel) si pertinent."

EXEMPLES DE RÉDACTION (style Blood / Journal of Clinical Oncology / Haematologica / Leukemia — format cible) :

Lymphome diffus grandes cellules B :
  titre_court : "POLARIX : pola-R-CHP améliore la SSP de 27 % vs R-CHOP en LDGCB"
  resume : "POLARIX (RCT, N=879, LDGCB IPI ≥2, 1re ligne) : polatuzumab védotin + R-CHP \
vs R-CHOP — SSP à 2 ans : 76,7 % vs 70,2 % (HR 0,73 ; IC95% 0,57–0,95 ; p=0,02). \
Pas de différence SG. Neuropathies périphériques grade ≥3 : 2,4 % vs 1,7 %. AMM EMA 2023 ; \
remboursé France si IPI ≥2 en 1re ligne."
  impact_pratique : "En pratique : pola-R-CHP désormais standard en 1re ligne LDGCB IPI ≥2 \
en France — vérifier remboursement SS et AMM en cours d'élargissement."

Myélome multiple rechute :
  titre_court : "IKEMA : isatuximab + Kd réduit la progression de 47 % vs Kd seul au MM rechute"
  resume : "IKEMA (RCT, N=302, MM en rechute/réfractaire 1-3 lignes, carfilzomib-dexaméthasone) : \
isatuximab IV + Kd vs Kd — SSP médiane non atteinte vs 19,2 mois (HR 0,53 ; IC95% 0,32–0,89 ; \
p=0,0007) à 20,7 mois de suivi. Réponse ≥ très bonne réponse partielle : 72 % vs 56 % (p=0,0011). \
AMM EMA ; remboursé France."
  impact_pratique : "À retenir : isatuximab-Kd à proposer en RCP dès la 1re rechute si carfilzomib \
non contre-indiqué — alternative à daratumumab-Kd pour patients sans anti-CD38 antérieur."

LLC — traitement de 1re ligne sans délétion 17p :
  titre_court : "ELEVATE-TN : acalabrutinib + obinutuzumab : SSP à 4 ans 78 % en LLC 1re ligne"
  resume : "ELEVATE-TN (RCT, N=535, LLC non traitée, sans délétion 17p) : acalabrutinib + \
obinutuzumab vs chlorambucil + obinutuzumab — SSP à 4 ans : 78 % vs 28 % (HR 0,10 ; \
IC95% 0,07–0,15 ; p<0,0001). Fibrillation auriculaire : 4,4 % (acalabrutinib) vs 3,7 %. \
AMM EMA ; remboursé France."
  impact_pratique : "En pratique : acalabrutinib + obinutuzumab devient une option de 1re ligne \
en LLC sans del17p/TP53 — choix entre ibrutinib, acalabrutinib ou venetoclax+obinutuzumab \
selon profil CV et préférence patient."

## EXEMPLES DE RÉDACTION
Style de référence : Blood, Haematologica, Leukemia, New England Journal of Medicine (hémato).
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "L'ajout de vénétoclax à l'azacitidine double la survie globale médiane dans la LAM non éligible à l'intensification — 14,7 vs 9,6 mois ; HR 0,66 ; IC95% 0,52–0,85 ; p<0,001 ; VIALE-A, RCT, n=431."
  impact_pratique : "En pratique : azacitidine + vénétoclax est le standard pour les LAM du sujet âgé ou fragile — vérifier myélogramme et mutations FLT3/IDH avant choix."

Bon exemple 2 :
  resume : "L'ibrutinib réduit la progression ou le décès de 42 % vs chlorambucil en LLC de novo — HR 0,58 ; IC95% 0,44–0,77 ; p<0,001 ; RESONATE-2, RCT, n=269, suivi médian 5 ans."
  impact_pratique : "À retenir : ibrutinib en 1re ligne LLC sans del17p — contrôler ECG et PA avant initiation, surveillance fibrillation auriculaire."

Bon exemple 3 :
  resume : "La thérapie cellulaire CAR-T (axicabtagène) atteint 58 % de réponse complète durable à 2 ans dans les LBDGC réfractaires — suivi médian 27 mois ; ZUMA-1, étude de phase II, n=101."
  impact_pratique : "En pratique : orienter précocement vers centre CAR-T les LBDGC en 2e ligne sans réponse — délai de fabrication 3–4 semaines à anticiper."

"""

_SPECIALTY_ADDENDUM_INFECTIOLOGIE = """\
CONTEXTE SPÉCIALITÉ — INFECTIOLOGIE ET MALADIES INFECTIEUSES

PUBLIC CIBLE : infectiologues hospitaliers, internistes avec compétence infectiologique, \
microbiologistes cliniques. CRITÈRE D'INCLUSION : ne retenir QUE les études qui changent ou \
affinent une décision thérapeutique (choix molécule, durée, stratégie de désescalade, \
indication de prophylaxie), une politique de santé publique, ou apportent une AMM utilisable \
en France. Exclure les études in vitro sans validation clinique, les études purement \
génomiques/mécanistiques, les épidémiologies descriptives sans intervention.

═══════════════════════════════════════════════════════════════════
I. VIH / SIDA ET PrEP
═══════════════════════════════════════════════════════════════════
ART et nouveaux schémas :
• Bictegravir/TAF/emtricitabine (BIC/TAF/FTC, Biktarvy®) : essais GS-US-380-1490/1489 \
→ non-infériorité vs comparateurs, très haute barrière génétique → standard de soin actuel.
• Dolutegravir+rilpivirine (Juluca®) bithérapie orale (SWORD-1/2) → AMM EMA 2017.
• Doravirine (INNTI 3e génération, Pifeltro®) : DRIVE-FORWARD/AHEAD/SHIFT → \
AMM EMA 2018 : option switch avec moins d'interactions enzymatiques.
• Lenacapavir (Sunlenca®, inhibiteur capside — mécanisme unique) : CAPELLA (rechute), \
ATLAS-2M (injection semestrielle en maintenance) → AMM EMA 2022 multi-résistants.
• Cabotegravir LA + rilpivirine LA (Cabenuva®) : ATLAS, FLAIR, ATLAS-2M → \
bithérapie injectable mensuelle puis bimestrielle → AMM EMA 2020. \
Retenir études de vie réelle, compliance, extension aux naïfs (CUSTOMIZE).
• Islatravir (NRTTI) + lenacapavir : essais phase 3 en cours — retenir résultats.
PrEP :
• CAB-LA (cabotegravir injectable 2 mois, HPTN 083/084) → supérieur TDF/FTC voie orale \
dans groupes à haut risque → AMM FDA 2021, EMA en évaluation → retenir tout update EMA.
• TDF/FTC oral : standard PrEP confirmé (iPrEx, PROUD, IPERGAY). Données F/TAF/FTC.
Comorbidités VIH :
• Risque cardiovasculaire (D:A:D, SMART), complications rénales (TDF vs TAF), \
cancer (Antiretroviral Therapy Cohort Collaboration) — retenir méta-analyses et cohortes.

═══════════════════════════════════════════════════════════════════
II. HÉPATITES VIRALES
═══════════════════════════════════════════════════════════════════
VHC (Hépatite C) :
• Pan-génotypiques : sofosbuvir/velpatasvir (SOF/VEL, Epclusa®, 12 semaines), \
glécaprévir/pibrentasvir (GLE/PIB, Maviret®, 8 semaines naïfs sans cirrhose). \
SOF/VEL/voxilaprévir (Vosevi®, 12 semaines retraitement pan-génotypique). SVR12 >95 %.
• Cirrhose décompensée : SOF/VEL ± ribavirine. Retenir données RVS et amélioration \
fibrose/fonction hépatique post-SVR12 (ASTRAL-4, ALLY-1).
VHB (Hépatite B) :
• Ténofovir alafénamide (TAF 25 mg, Vemlidy®) vs TDF : moins néphrotoxique/osseux, \
non-infériorité virologique (GS-US-320-0108/0110). Standard actuel chez >60 ans/IR/ostéoporose.
• Tenofovir disoproxil : toujours référence grossesse VHB (prévention transmission materno-fœtale).
• Durée traitement, arrêt des analogues (perte AgHBs) : retenir méta-analyses ESCMID 2023.
VHD (Hépatite Delta) :
• Bulevirtide (Hepcludex®, inhibiteur NTCP) : MYR204, MYR301 → AMM EMA 2020 (conditionnelle) \
→ confirmation 2023. Seul traitement AMM VHD. Retenir toutes nouvelles données.
VHE (Hépatite E) :
• Ribavirine dans VHE chronique immunodéprimé : retenir études de cohorte.

═══════════════════════════════════════════════════════════════════
III. ANTIBIORÉSISTANCE ET ANTIBIOTHÉRAPIE DES BMR
═══════════════════════════════════════════════════════════════════
Entérobactéries résistantes :
• Ceftazidime-avibactam (CAZ-AVI, Avycaz®/Zavicefta®) : actif KPC + OXA-48 \
mais PAS MBL (NDM/VIM/IMP). REPRISE trial, RECLAIM → AMM EMA 2016.
• Aztreonam-avibactam (ATM-AVI, Aztreonam+Avycaz® combinaison) : actif MBL + KPC + OXA-48 \
→ AMM FDA 2023 (REVISIT trial), EMA soumis → retenir toute publication sur usage.
• Imipénème-cilastatine-relebactam (IMR, Recarbrio®) : actif KPC, pas MBL → AMM EMA 2020.
• Cefidérocol (Fetroja®, sidérophore céphalosporine) : actif sur gram- MDR dont MBL \
→ AMM EMA 2020 (APEKS-NP). Retenir données comparatives en vie réelle.
Pseudomonas aeruginosa / PABL :
• Ceftolozane-tazobactam (C/T, Zerbaxa®) : actif PABL mais pas entérobactéries KPC \
→ AMM EMA 2015, ASPECT-NP extension. Retenir données résistance acquise en cours de traitement.
SARM et coques gram-positifs :
• Ceftaroline (Teflaro®/Zinforo®) : SARM communautaire, pneumocoque multi-résistant \
→ AMM EMA 2012. Daptomycine (endocardite droite SARM). Retenir essais comparatifs.
• Oritavancine, télavancine, dalbavancine (glycopeptides longue durée) : \
dose unique ou bi-hebdomadaire → retenir données de pratique réelle (IOA, endocardite).
Clostridium difficile :
• Fidaxomicine (Dificlir®) > vancomycine orale pour prévention récidive → AMM EMA 2011. \
Bézlotoxumab (Zinplava®, anti-toxine B) pour prévention récidive → AMM EMA 2016. \
Microbiome fécal (FMT) → remboursement en France 2024 — retenir tout guideline.
EUCAST / ECDC :
• Retenir systématiquement les nouvelles données de surveillance EARS-Net publiées dans \
Eurosurveillance ou Clin Microbiol Infect modifiant les probabilités de résistance.

═══════════════════════════════════════════════════════════════════
IV. INFECTIONS FONGIQUES INVASIVES
═══════════════════════════════════════════════════════════════════
• Échinocandines : caspofungine, micafungine, anidulafungine — standard candidose invasive \
(ESCMID 2023). Rezafungin (échinocandine longue durée — 1 fois/semaine) : AMM FDA 2023, \
EMA soumis — retenir essais comparatifs (STRIVE) et résultats EMA.
• Ibrexafungerp (Brexafemme®, glucan synthase inhibiteur oral) : AMM FDA 2021 \
vulvo-vaginite candidosique — retenir données efficacité, résistances échinocandines.
• Olorofim (inhibiteur DHODH oral) : actif Aspergillus résistants azolés → \
essai phase 3 en cours — retenir résultats (AMM attendue).
• Aspergillose invasive : voriconazole vs isavuconazole (VITALS) — non-infériorité + \
meilleure tolérance isavuconazole → AMM EMA 2015. Standard actuel immunodéprimé.
• Mucormycose : isavuconazole (IsAspA) → alternative liposomal amphotéricine B → AMM EMA.
• Guidelines ESCMID 2022 candidoses invasives, 2023 aspergilloses : retenir.

═══════════════════════════════════════════════════════════════════
V. SEPSIS ET INFECTIONS SÉVÈRES
═══════════════════════════════════════════════════════════════════
• Surviving Sepsis Campaign (SSC) 2021 : bundle 1h (hémocultures, lactate, ATB dans 1h, \
remplissage 30ml/kg cristalloïdes si lactate ≥4 ou hypotension, vasopresseurs si PAS<65mmHg) \
→ référence réglementaire mondiale. Retenir toute étude validant/modifiant ce bundle.
• Endocardite infectieuse : guidelines ESC 2023 (mise à jour majeure) → retenir.
• Traitement antibiotique oral dans les IOA (OVIVA trial → non-infériorité IV vs oral \
après 7j) — retenir nouvelles méta-analyses confirmant ce résultat.
• Antibiothérapie désescalade guidée par microbiologie/biomarqueurs (PCT) : \
retenir essais randomisés sur durée et désescalade.
• Antibioprophylaxie chirurgicale : retenir guidelines SFAR/SPILF actualisées.

═══════════════════════════════════════════════════════════════════
VI. TUBERCULOSE ET MYCOBACTÉRIOSES
═══════════════════════════════════════════════════════════════════
• TB MDR/XDR :
  — BPaL (Bédaquiline 400mg/200mg + Prétomanid 200mg + Linézolide 1200mg/600mg) : \
    TB-PRACTECAL, ZeNix → 90 % succès XDR en 6 mois → AMM FDA 2019 / EMA 2020 prétomanid \
    exclusivement dans ce régime. Retenir tout update doses linézolide (600mg).
  — Bédaquiline (Sirturo®, AMM EMA 2014) seul dans les régimes courts (STREAM, endTB).
  — Délamanid (Deltyba®, AMM EMA 2014) comme alternative dans les régimes BDQ-contenant.
• TB sensible : rifampicine (RIFAPENTIN, TBTC Study 26) schémas courts 4 mois. \
  Pyrazinamide (toxicité hépatique dose-dépendante) — retenir études optimisation PK/PD.
• Mycobactéries non tuberculeuses (MNT) : MAC pulmonaire (amikacine liposomale inhalée \
Arikayce® → AMM EMA 2020, CONVERT trial) — retenir données vie réelle.

═══════════════════════════════════════════════════════════════════
VII. IST, PALUDISME, MALADIES TROPICALES
═══════════════════════════════════════════════════════════════════
IST :
• Gonorrhée résistante : ceftriaxone 1g IM seul (pas de combinaison azithromycine en routine \
car résistance → IUSTI 2022/EUCAST) — retenir études résistances et nouveaux traitements \
(zoliflodacin, gepotidacin — phase 3 en cours).
• Syphilis : benzathine pénicilline G 2,4 MU IM toujours standard. Retenir guidelines \
IUSTI 2022, nouvelles données sur doxycycline doxyprophylaxie (DoxyPEP) post-exposition IST \
(DOXYVAC, IPERGAY OLE) → AMM FDA non encore obtenue.
• Chlamydia/LGV : doxycycline 21j dans LGV (IUSTI 2022). Retenir données azithromycine \
résistance partielle (traitement dose unique toujours efficace Ct).
Paludisme :
• Artéméther-luméfantrine : toujours 1re ligne Plasmodium falciparum non compliqué dans \
la majorité des pays. Résistances artémisinine (Cambodge, Afrique de l'Est K13) — retenir.
• RTS,S/AS01E (Mosquirix®, GSK) : AMM EMA 2015, recommandé OMS oct 2021 pour P. falciparum \
en Afrique subsaharienne — vaccin 4 doses, réduction paludisme 40 % enfants. Retenir \
données de mise en œuvre, R21/Matrix-M (efficacité 75 % — OMS soumission).
• Tafénoquine (Krintafelone®/Arakoda®) : prophylaxie + traitement radical vivax \
→ AMM FDA 2018/EMA 2022 — retenir données activité hépatique.
COVID-19 et viroses émergentes :
• Nirmatrelvir/ritonavir (Paxlovid®) : EPIC-HR → 89 % réduction hospitalisations patients \
à risque. Standard antiviral COVID-19 oral. Retenir données résistances, variants.
• Monkeypox/Mpox : tecovirimat (TPOXX®) → données PALM007, retenir études.
CMV / infections opportunistes :
• Letermovir (Prevymis®) prophylaxie CMV allogreffe → AMM EMA 2017 → retenir études \
extension sur traitement CMV maladie.

═══════════════════════════════════════════════════════════════════
VIII. RÈGLES DE SCORING SPÉCIFIQUES
═══════════════════════════════════════════════════════════════════
• Score ≥8 : essai randomisé ou méta-analyse modifiant un standard de soin SPILF/IDSA/ESCMID/ESC, \
AMM EMA avec impact praticien immédiat, guideline de société savante nationale/internationale.
• Score 6-7 : RCT multicentrique ≥200 patients avec endpoint clinique (mortalité, guérison, \
récidive, SVR), méta-analyse ESCMID/IDSA, données de registre national modifiant la pratique.
• Score ≤5 (exclure) : études in vitro/ex vivo sans validation clinique, étude de prévalence \
de résistance sans impact thérapeutique direct, modèles prédictifs non validés cliniquement, \
cas cliniques/séries <20 patients.
• Contexte FRANÇAIS : AMM EMA > FDA seule ; recommandations SPILF/HAS/CMIT obligatoires ; \
données françaises SNDS/registres RAISIN-BMR ; signalement ANSM ATU/AC si pertinent."

EXEMPLES DE RÉDACTION (style Clinical Infectious Diseases / Lancet Infectious Diseases / JAC — format cible) :

Antibiothérapie — durée courte :
  titre_court : "Pneumonie communautaire sévère : 5j amoxicilline non inférieur à 10j"
  resume : "SHORTEN (RCT, N=312, PAC sévère hospitalisée, CURB-65 ≥3, réponse clinique à J3) : \
amoxicilline-clavulanate 5j vs 10j — échec clinique à J30 : 9,0 % vs 8,4 % \
(différence 0,6 % ; IC90% −4,6–5,7 ; non-inférieur). Durée médiane hospitalisée réduite \
de 1,2 jour. Pas de différence mortalité ni résistance émergente à 90j."
  impact_pratique : "En pratique : antibiothérapie 5j pour toute PAC hospitalisée avec bonne \
réponse clinique à J3 — arrêt prématuré non justifié seulement si immunodépression \
ou agent atypique identifié."

Infection fongique invasive — prophylaxie :
  titre_court : "Isavuconazole prophylaxie aspergillose en greffe allogénique : non inférieur au voriconazole"
  resume : "CONDOR (RCT, N=588, greffe allogénique CSH conditionnement myéloablatif) : isavuconazole \
200 mg/j vs voriconazole — incidence aspergillose invasive prouvée/probable à J100 : \
3,2 % vs 3,9 % (non-inférieur ; HR 0,82 ; IC95% 0,43–1,56). Isavuconazole associé à \
moins d'interactions médicamenteuses (CYP3A4 faible inhibition) et moins de perturbations visuelles."
  impact_pratique : "En pratique : isavuconazole alternative au voriconazole en prophylaxie \
antifongique post-greffe CSH — préférer si polymédication ou risque hépatotoxique \
(moins d'interactions CYP)."

Résistances bactériennes — antibiothérapie de recours :
  titre_court : "Ceftazidime-avibactam vs meropénem BSBLRE : mortalité à 28j identique"
  resume : "REPRISE (étude de cohorte apparillée, N=240, infections à Klebsiella BSBLRE ou \
Pseudomonas MDR confirmé, France/Espagne) : ceftazidime-avibactam vs meropénem \
(souche sensible) — mortalité à 28j : 22 % vs 24 % (OR 0,90 ; IC95% 0,54–1,51 ; p=0,68). \
Sélection de résistances sous ceftazidime-avibactam : 4,2 % (mutation OXA-48)."
  impact_pratique : "En pratique : réserver ceftazidime-avibactam aux infections à Klebsiella \
BSBLRE documentées — antibiogramme impératif avant usage ; signaler toute résistance \
acquise à l'infectiologue référent."

## EXEMPLES DE RÉDACTION
Style de référence : Clinical Infectious Diseases, Lancet Infectious Diseases, Journal of Antimicrobial Chemotherapy.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "Le traitement de 5 jours par nirmatrelvir-ritonavir réduit le risque d'hospitalisation ou décès de 89 % chez les COVID-19 à risque — HR 0,11 ; IC95% 0,04–0,27 ; p<0,0001 ; EPIC-HR, RCT, n=2 246, non vaccinés."
  impact_pratique : "En pratique : nirmatrelvir dès symptômes (<5 j) chez tout patient à risque élevé — vérifier interactions médicamenteuses (statines, anticoagulants) avant prescription."

Bon exemple 2 :
  resume : "La durée courte d'antibiotiques (5 j amoxicilline) est non-inférieure à 10 j dans les pneumonies communautaires légères à modérées — taux de guérison 88 % vs 90 % ; RR 0,98 ; IC95% 0,93–1,04 ; RCT, n=580."
  impact_pratique : "À retenir : 5 jours suffisent pour les PAC sans critères de gravité — éviter la pression de sélection inutile, réévaluer à J3 si non-amélioration."

Bon exemple 3 :
  resume : "La prophylaxie par doxycycline post-exposition réduit de 78 % les IST bactériennes chez les HSH sous PrEP — OR 0,22 ; IC95% 0,09–0,50 ; p<0,001 ; doxy-PEP, RCT, n=501, suivi 12 mois."
  impact_pratique : "En pratique : proposer doxy-PEP 200 mg dans les 72 h après rapport non protégé chez HSH à haut risque — information sur résistances et suivi ECBU trimestriel."

"""

_SPECIALTY_ADDENDUM_INFIRMIERS = """\
CONTEXTE SPÉCIALITÉ — INFIRMIERS ET INFIRMIÈRES (IDE)

PUBLIC CIBLE : infirmiers et infirmières diplômés d'État (IDE), infirmiers en pratique avancée \
(IPA), infirmiers de bloc opératoire (IBODE), infirmiers anesthésistes (IADE), puéricultrices. \
CRITÈRE D'INCLUSION : ne retenir QUE les études qui modifient ou valident une pratique infirmière \
concrète (protocole de soin, technique, outil d'évaluation, formation). Exclure les études \
purement médicales sans rôle infirmier, les études sociologiques sans implications pratiques.

═══════════════════════════════════════════════════════════════════
I. PLAIES, CICATRISATION ET SOINS DE PEAU
═══════════════════════════════════════════════════════════════════
• Prévention et traitement des escarres : classification EPUAP/NPIAP/PPPIA 2019 (stades I-IV + \
non classable + tissu profond) — référence réglementaire. Échelle de Braden ≤18 = à risque. \
Matelas à air dynamique, repositionnements toutes les 2h, protection proéminences osseuses. \
Retenir tout essai sur prévention (nouveaux dispositifs, protocoles repositionnement, nutrition).
• Plaies chroniques : ulcère veineux (compression multicouche, débridement) ; \
ulcère artériel (pas de compression si IPS <0,6) ; pied diabétique (classification Wagner, \
Texas — décharge, revascularisation, antibiothérapie locale). Framework TIME. \
Retenir méta-analyses sur types de pansements (hydrocolloïde, hydrogel, alginate, mousse, PHMB, \
argent, iode, miel médical, fibres d'hydrofibre).
• Thérapie par pression négative (TPN/VAC) : retenir RCTs sur efficacité par type de plaie.
• Prévention des lésions cutanées péristomiales et des dermites incontinence (IAD) : \
produits barrières, classification EPUAP/IAD — retenir.
• Cicatrices hypertrophiques / chéloïdes : retenir essais sur compression et silicone.

═══════════════════════════════════════════════════════════════════
II. DOULEUR ET SOINS PALLIATIFS
═══════════════════════════════════════════════════════════════════
• Évaluation de la douleur : EVA/EN (patients communicants), DOLOPLUS-2, Algoplus (personnes \
âgées), EVENDOL/FLACC (enfants), BPS/CPOT (non communicants REA) — retenir études de \
validation et comparaison des échelles.
• Douleurs procédurales : MEOPA (mélange équimolaire O2/N2O), crème EMLA, saccharose \
nourrisson, distraction (hypnoanalgésie) — retenir RCTs par type de soin (pansement, \
ponction, mobilisation).
• Protocoles de titration morphinique : retenir études sur protocoles IDE de titration \
rapide dans la douleur aiguë sévère.
• Soins palliatifs et fin de vie : loi Claeys-Leonetti 2016 (directives anticipées, \
sédation profonde et continue jusqu'au décès SPC) — retenir études sur confort du mourant, \
prise en charge infirmière de l'agonie, soins de bouche.
• Gestion de la douleur chronique : retenir études sur rôle IDE dans l'accompagnement \
des douleurs cancéreuses (patch fentanyl, rotation opioïdes, hypnose, TENS).

═══════════════════════════════════════════════════════════════════
III. PRÉVENTION DES INFECTIONS NOSOCOMIALES
═══════════════════════════════════════════════════════════════════
• Hygiène des mains : OMS 5 moments (avant contact patient, avant geste aseptique, \
après risque d'exposition, après contact patient, après contact environnement) — \
retenir études sur compliance et efficacité des programmes d'amélioration.
• PAVM (pneumonie associée à la ventilation mécanique) : bundle PAVM (position \
demi-assise ≥30°, pression ballonnet 25-30 cmH2O, hygiène buccale chlorhexidine 0,12%, \
arrêt quotidien sédation) — retenir RCTs composantes du bundle.
• Infections sur cathéter veineux central (CRBSI/CLABSI) : bundle pose \
(précautions maximales d'asepsie, site sous-clavière > jugulaire > fémorale), \
entretien (changement voies et robinets) — retenir études sur durée de port, verrous \
antibiotiques, nouveaux pansements (CHG-gel, CHG-éponge).
• Infections urinaires sur sonde (CAUTI) : retrait précoce, soins de méat, sondes \
imprégnées antibiotiques/argent — retenir méta-analyses.
• Entérobactéries résistantes en milieu de soins (EBLSE/EPC) : précautions contact \
complémentaires, cohorting, dépistage rectal — retenir études d'impact organisationnel \
sur la transmission.

═══════════════════════════════════════════════════════════════════
IV. SOINS CRITIQUES ET RÉANIMATION (RÔLE INFIRMIER)
═══════════════════════════════════════════════════════════════════
• Délire en réanimation : CAM-ICU (outil de dépistage infirmier), modèle ABCDEF bundle \
(Awakening, Breathing, Coordination, Delirium, Early mobility, Family) → retenir RCTs \
sur implémentation et résultats (durée ventilation, LOS, fonctions cognitives).
• Mobilisation précoce en réanimation : retenir essais sur protocoles IDE de \
mobilisation et résultats (force musculaire, qualité de vie post-REA).
• Soins de confort en réanimation / humanisation : lumière naturelle, rythme \
circadien, présence famille, communication patient intubé — retenir études.
• Gestion des alarmes monitorage : alarm fatigue — retenir études sur protocoles \
de paramétrage et impact sur sécurité.

═══════════════════════════════════════════════════════════════════
V. ÉDUCATION THÉRAPEUTIQUE ET SUIVI (ETP)
═══════════════════════════════════════════════════════════════════
• ETP en maladies chroniques (diabète, ICC, BPCO, oncologie, stomies) : HAS 2007 \
(programme autorisé ARS, bilan éducatif partagé). Retenir méta-analyses sur efficacité \
des programmes ETP infirmiers sur critères cliniques (HbA1c, hospitalisations).
• Adhérence thérapeutique : interventions infirmières brèves, entretien motivationnel, \
outils numériques (télé-suivi) — retenir RCTs multicentriques.
• Stomies (colostomie, iléostomie, urétérostomie) : éducation pré- et post-opératoire, \
types d'appareillage, complications péristomiales — retenir guidelines WOCN/ASCRS.
• Insuffisance cardiaque : prise en charge infirmière (pesée quotidienne, régime \
hyposodé, adaptation diurétiques sur protocole) — retenir essais sur télé-suivi IDE.

═══════════════════════════════════════════════════════════════════
VI. SÉCURITÉ DES SOINS, FORMATION ET ORGANISATION
═══════════════════════════════════════════════════════════════════
• Erreurs médicamenteuses : double contrôle, code-barres, systèmes automatisés \
(dispensation nominative, piluliers) — retenir études d'impact sur taux d'erreur.
• Événements indésirables associés aux soins (EIAS) : checklist HAS / OMS bloc \
opératoire, déclaration des EIG (ANSM/HAS), culture sécurité équipe — retenir.
• Ratio IDE/patients (RN4CAST) : retenir études de cohorte sur mortalité et qualité \
des soins selon ratio. Burnout infirmier et turn-over : retenir méta-analyses récentes.
• Simulation en soins infirmiers : haute-fidélité (mannequin, standardized patient), \
débriefing, impact sur compétences techniques — retenir RCTs.
• Tenue de la dossier infirmier / transmissions : retenir études sur traçabilité \
et continuité des soins.

═══════════════════════════════════════════════════════════════════
VII. RÈGLES DE SCORING SPÉCIFIQUES
═══════════════════════════════════════════════════════════════════
• Score ≥8 : méta-analyse modifiant un protocole de soins infirmiers validé HAS/SFAP/ \
EPUAP/EWMA, guideline internationale applicable en France, RCT multicentrique ≥500 patients \
sur critère de résultat clinique (infection, escarre, douleur, mortalité).
• Score 6-7 : RCT ou cohorte ≥100 patients avec endpoint clinique infirmier pertinent, \
étude de validation d'une échelle d'évaluation infirmière, étude d'implémentation de bundle.
• Score ≤5 (exclure) : études qualitatives seules, études d'opinion/satisfaction \
sans critère clinique, études monocentriques <50 patients, articles de formation pure \
sans validation clinique.
• Contexte FRANÇAIS : recommandations HAS/SFAP/SRLF applicables en France ; données \
françaises (IQSS, SIPAQSS) ; décrets et textes réglementaires IDE (exercice professionnel)."

EXEMPLES DE RÉDACTION (style Journal of Advanced Nursing / IJNS / Soins — format cible) :

Prévention escarre — protocole repositionnement :
  titre_court : "Repositionnement toutes les 2h vs 4h : pas de différence en escarre — essai TURN"
  resume : "TURN (RCT, N=942, patients hospitalisés à haut risque d'escarre, matelas haute densité) : \
repositionnement toutes les 2h vs 4h — incidence escarre grade ≥2 à J30 : 3,9 % vs 4,5 % \
(RR 0,87 ; IC95% 0,55–1,38 ; p=0,55 ; non-significatif). Confort et sommeil significativement \
améliorés dans le groupe 4h. Matelas adapté = facteur clé, fréquence secondaire."
  impact_pratique : "En pratique : avec un matelas haute densité adapté, repositionnement toutes \
les 4h suffisant — à adapter selon état cutané, mobilité et confort du patient."

Douleur post-opératoire — rôle infirmier :
  titre_court : "Évaluation systématique de la douleur par IDE réduit le recours aux opioïdes de 18 %"
  resume : "Étude observationnelle prospective (N=1 230, chirurgie élective 12 services, France) : \
évaluation douleur systématique par IDE (EN toutes les 4h) + protocole d'administration \
anticipée vs évaluation à la demande — recours opioïdes post-op −18 % (p<0,01) ; \
satisfaction patient +12 points NPS (p<0,001). Durée de séjour non modifiée."
  impact_pratique : "En pratique : mettre en place une évaluation protocolisée de la douleur \
(EN toutes les 4h les 48h post-op) et un accès aux antalgiques sans délai de prescription."

Décret compétences IDE — prescription adaptée :
  titre_court : "Décret 2023-135 : IDE habilité à renouveler certaines ordonnances en EHPAD"
  resume : "Décret n° 2023-135 du 23 février 2023 (JO du 24 février) : extension de la compétence \
IDE au renouvellement des prescriptions médicales pour 10 classes de médicaments courants \
(antihypertenseurs, antidiabétiques, anticoagulants) dans les structures médico-sociales \
(EHPAD, SSIAD) après formation validée. Applicable depuis le 1er mars 2023."
  impact_pratique : "En pratique : formation à la prescription adaptée IDE désormais opposable \
en EHPAD — vérifier les habilitations de l'équipe et mettre à jour le protocole de \
coopération institutionnel."

## EXEMPLES DE RÉDACTION
Style de référence : Journal of Advanced Nursing, International Journal of Nursing Studies, BMJ Quality & Safety.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "Un protocole infirmier structuré de prévention des escarres réduit l'incidence de 47 % en soins intensifs — RR 0,53 ; IC95% 0,38–0,74 ; p<0,001 ; essai contrôlé, n=1 204, 6 services ICU."
  impact_pratique : "En pratique : mettre en place le protocole de repositionnement toutes les 2 h + évaluation Braden à l'admission — former l'équipe aux points de pression critiques."

Bon exemple 2 :
  resume : "La télésurveillance infirmière post-opératoire réduit les réhospitalisations à 30 jours de 31 % — OR 0,69 ; IC95% 0,52–0,91 ; p=0,008 ; étude de cohorte, n=2 890, chirurgie cardiaque."
  impact_pratique : "À retenir : appel infirmier à J3 et J7 post-sortie réduit significativement les ré-admissions — prioriser les patients sans aidant et comorbidités cardiaques."

Bon exemple 3 :
  resume : "La check-list de vérification médicamenteuse par l'infirmier diminue les erreurs d'administration de 62 % en médecine interne — IRR 0,38 ; IC95% 0,27–0,54 ; audit avant-après, n=14 000 administrations."
  impact_pratique : "En pratique : imposer la double vérification (identité + voie + dose) pour les médicaments à risque — anticoagulants, insuline, électrolytes concentrés."

"""

_SPECIALTY_ADDENDUM_KINESITHERAPIE = """\
CONTEXTE SPÉCIALITÉ — KINÉSITHÉRAPIE ET RÉÉDUCATION FONCTIONNELLE

PUBLIC CIBLE : masseurs-kinésithérapeutes (MK), kinésithérapeutes spécialisés (sport, \
neurologie, cardio-respiratoire, périnéal, pédiatrie). CRITÈRE D'INCLUSION : ne retenir QUE \
les études qui modifient ou valident une technique, un protocole de rééducation ou un outil \
d'évaluation utilisable en pratique kinésithérapeutique. Exclure les études purement \
chirurgicales sans comparaison avec la rééducation, les études fondamentales, les approches \
sans validation clinique.

═══════════════════════════════════════════════════════════════════
I. RÉÉDUCATION MUSCULO-SQUELETTIQUE (MSK)
═══════════════════════════════════════════════════════════════════
Lombalgie :
• Lombalgie commune aiguë : conseils d'activité + AINS > repos strict. Guidelines ESC/HAS 2019.
• Lombalgie chronique : approche biopsychosociale = référence (modèle de peur-évitement, \
thérapie cognitive-fonctionnelle CFT, reconditionnement à l'effort, éducation neurophysiologique \
de la douleur PNE, stabilisation lombaire) — retenir méta-analyses comparatives. \
Éviter terme "core stability" sans précision. Pilates : données modérées.
• Lombalgie et chirurgie : rééducation seule non-inférieure pour la plupart des hernies \
discales — retenir RCTs.
Cervicalgie / épaule :
• Cervicalgie mécanique : mobilisation cervicale + exercices actifs > passive seule. \
Manipulation cervicale haute : efficace douleur aiguë, contre-indiquée si risque artère \
vertébrale (tests cliniques — IFOMPT 2020). Retenir nouvelles données sur sécurité.
• Syndrome d'accrochage sous-acromial (SAS) : exercices actifs seuls = corticoïdes locaux \
à 3 mois (GRASP trial, CODA trial) → pas de supériorité de la chirurgie par arthroscopie \
pour la plupart des cas (Cochrane 2019). Retenir confirmations.
• Coiffe des rotateurs : rééducation guidée > simple watching and waiting pour rupture \
partielle. Instabilité glénohumérale : exercices de stabilisation dynamique.
Genou / hanche / cheville :
• Tendinopathie achilléenne : programme excentrique (Alfredson, 3×15 deux fois/jour) = \
référence (Cochrane). HEAVY SLOW RESISTANCE (HSR) non-inférieure, meilleure tolérance. \
Retenir nouvelles données (NICE, JOSPT 2022 CPG).
• Tendinopathie patellaire : exercices excentriques + isométriques (pour analgésie \
immédiate avant compétition). Retenir données HSR.
• Genou post-PTG/LCA : protocoles de réhabilitation accélérée (ERAS) → retenir RCTs. \
Critères de retour au sport post-LCA : force, tests fonctionnels.
• Entorse LLE cheville : protocole PEACE & LOVE (2020) — Protect/Elevate/Avoid-NSAID/ \
Compress/Educate puis Load/Optimism/Vascularisation/Exercise. Retenir études sur \
prophylaxie rechute (exercices proprioception).
• Syndrome fémoro-patellaire : renforcement VMO, contrôle neuromusculaire (JOSPT 2019 CPG).
Arthrose :
• Gonarthrose/coxarthrose : exercices thérapeutiques = traitement 1re ligne (EULAR, OARSI 2019). \
Retenir méta-analyses sur type/intensité optimale d'exercice.

═══════════════════════════════════════════════════════════════════
II. RÉÉDUCATION NEUROLOGIQUE
═══════════════════════════════════════════════════════════════════
AVC :
• Fenêtre thérapeutique précoce : rééducation intensive précoce (≤72h) améliore pronostic \
fonctionnel. Soins intensifs de rééducation (SUNR) — retenir études sur modèles organisationnels.
• Thérapie par contrainte induite du mouvement (TCI/CIMT) : EXCITE trial → supérieure \
à la rééducation conventionnelle pour le membre supérieur en phase chronique. \
mCIMT (modified CIMT) adapté phase subaiguë — retenir méta-analyses récentes.
• Thérapies robotiques et exosquelettes (Lokomat, Armeo) : retenir RCTs vs kiné conventionnelle.
• Stimulation non invasive (TMS, tDCS) en rééducation AVC : retenir méta-analyses.
• Réalité virtuelle (VR/AR) : retenir RCTs multicentriques sur équilibre et membre supérieur.
Maladie de Parkinson :
• LSVT BIG (amplification du mouvement) : RCTs sur vitesse de marche, volume mouvement, \
UPDRS — retenir nouvelles données et variantes (PD-WEBB, HiBalance).
• Danse thérapeutique (tango argentin) et tai-chi : retenir méta-analyses équilibre/chute.
• Treadmill training avec ou sans poids corporel supporté : retenir études sur freezing of gait.
SEP (Sclérose en plaques) :
• Exercices aérobies + résistance : retenir méta-analyses sur fatigue, marche, spasticité.
• Fatigue SEP : exercices en piscine (moins de thermorégulation), thérapies cognitives. \
Fampridine améliore la marche mais n'est pas un outil kiné.
• FES (Functional Electrical Stimulation) pour drop foot (ODFS, WalkAide) : retenir RCTs.
Blessés médullaires :
• FES locomotion, stimulation épidurale (STIMO, Louisville) — nouvelles données retenir.

═══════════════════════════════════════════════════════════════════
III. RÉÉDUCATION CARDIO-RESPIRATOIRE
═══════════════════════════════════════════════════════════════════
BPCO :
• Réhabilitation respiratoire : améliore capacité d'effort (test 6MWT), dyspnée (MRC), QoL \
(SGRQ) sans modifier VEMS — GOLD 2024 recommandation A. Maintien bénéfice à 12 mois si \
programme de maintenance. Retenir tout RCT sur format, durée, lieu (hôpital/domicile).
• Drainage bronchique : ELTGOL (Expiration Lente Totale Glotte Ouverte en Latéral), AFE \
(Augmentation du Flux Expiratoire), DAA (Drainage Autogène Assisté) > aspirations \
trachéobronchiques. Recommandations HAS/SPLF.
• Ventilation non invasive (VNI) : kinésithérapeute acteur clé mise en place et surveillance \
— retenir études sur interface, synchronisation, sevrage.
Insuffisance cardiaque :
• Réhabilitation cardiaque post-IDM / ICC : réduction mortalité CV et hospitalisations \
(Cochrane 2021). Retenir données sur format haute intensité (HIIT vs MICT), téléréhabilitation.
Mucoviscidose :
• Kinésithérapie respiratoire quotidienne (Flutter, Acapella, gilet à haute fréquence) : \
retenir études comparatives. Décongestionnants osmotiques (sérum hypertonique 7%) : \
retenir guidelines ELF/ECFS.
Périnéal et pelvi-périnéal :
• Incontinence urinaire d'effort (IUE) : rééducation périnéale (Kegel + biofeedback EMG) \
= traitement 1re ligne HAS 2003 / Cochrane 2018 (43 RCTs). Retenir études sur intensité \
et durée optimale du programme.
• Rééducation post-prostatectomie totale : démarrage précoce (J1 post-op) — retenir RCTs.

═══════════════════════════════════════════════════════════════════
IV. NOUVELLES TECHNOLOGIES ET TÉLÉRÉÉDUCATION
═══════════════════════════════════════════════════════════════════
• Télérééducation (telerehabilitation) : COVID-19 a accéléré l'adoption — retenir RCTs \
comparant télé vs présentiel sur lombalgie, PTG, AVC. Non-infériorité pour la plupart des \
pathologies stable (Cochrane 2022).
• Intelligence artificielle en kinésithérapie : analyse de mouvement automatisée, \
feedback visuel — retenir premières études cliniques randomisées.
• Réalité virtuelle (VR) pour équilibre et rééducation neurologique : retenir méta-analyses.
• Biofeedback EMG et sEMG : retenir RCTs dans incontinence, périnée, MSK.
• TENS / neuromodulation : retenir méta-analyses sur douleur chronique (lombalgie, fibromyalgie).

═══════════════════════════════════════════════════════════════════
V. RÈGLES DE SCORING SPÉCIFIQUES
═══════════════════════════════════════════════════════════════════
• Score ≥8 : méta-analyse Cochrane ou méta-analyse réseau (NMA) sur technique kiné avec \
endpoint clinique (VAS, WOMAC, MRC, 6MWT, FIM, BI), Clinical Practice Guideline JOSPT/HAS/ \
SOFMER modifiant la pratique, RCT multicentrique ≥300 patients.
• Score 6-7 : RCT ≥60 patients avec outcome clinique pertinent (douleur, fonction, retour \
au travail/sport), revue systématique ≥10 études, guideline société savante nationale.
• Score ≤5 (exclure) : études in vitro/animal, études biomécanique pure sans application \
clinique, études sur <20 patients, études d'opinion sans validation clinique.
• Contexte FRANÇAIS : recommandations HAS (lombalgie, rééducation AVC, incontinence, \
réhabilitation BPCO) ; recommandations SOFMER/SPLF/SFC applicables en France ; données \
françaises PMSI-MPR, registres SOFMER. Décret d'actes kinésithérapiques (nomenclature NGAP)."

EXEMPLES DE RÉDACTION (style Physical Therapy / JOSPT / Manual Therapy / BJSM — format cible) :

Lombalgie chronique — approche active :
  titre_court : "Lombalgie chronique : exercice actif > physiothérapie passive — méta-analyse"
  resume : "Méta-analyse Cochrane (N=12 412, 249 RCTs, lombalgie chronique non spécifique) : \
exercice actif vs traitement passif (TENS, ultrasons, massage) — réduction douleur \
EVA −1,3 points (IC95% −1,7/−0,9) et incapacité (Oswestry) −4,5 points à 12 semaines. \
Bénéfice similaire quelle que soit la modalité d'exercice (résistance, stretching, yoga). \
HAS 2019 recommande l'activation précoce."
  impact_pratique : "En pratique : prescrire un programme d'exercice actif supervisé dès la 1re \
consultation — les techniques passives seules ne modifient pas l'histoire naturelle."

Rupture du LCA — rééducation pré-opératoire :
  titre_court : "Préhabilitation LCA : retour au sport 3 semaines plus tôt et meilleure force quadricipitale"
  resume : "RCT (N=154, rupture LCA isolée, délai chirurgie 6-8 semaines) : préhabilitation \
(6 séances kin + exercices quotidiens) vs aucune rééducation pré-op — force quad à J30 post-op \
: 68 % vs 55 % du côté sain (p=0,01) ; délai retour au sport : 7,2 vs 7,9 mois (−3 semaines, \
p=0,04). Résultats IKDC à 6 mois : 68 vs 58 points (p=0,03)."
  impact_pratique : "En pratique : initier systématiquement 6 séances de préhabilitation ciblée \
quad/ischio dès le diagnostic — améliore significativement la récupération fonctionnelle \
post-opératoire."

Techniques manuelles cervicalgie :
  titre_court : "Manipulation cervicale vs mobilisation : efficacité équivalente, profil sécurité comparable"
  resume : "Méta-analyse (N=2 517, 23 RCTs, cervicalgie mécanique non radiculaire aiguë/subaiguë) : \
manipulation (HVLA) vs mobilisation (amplitude réduite) — réduction EVA à 4 semaines : \
−1,8 vs −1,6 points (différence 0,2 ; IC95% −0,3–0,7 ; non significatif). \
Complications graves (AVC vertébrobasilaire) : <1/1 000 000 séances pour les deux techniques."
  impact_pratique : "En pratique : manipulation et mobilisation sont équivalentes en efficacité \
et sécurité — adapter selon préférence patient et compétence du thérapeute."

## EXEMPLES DE RÉDACTION
Style de référence : Journal of Physiotherapy, Physical Therapy, British Journal of Sports Medicine.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "La kinésithérapie intensive précoce (J1 post-op) réduit la durée de séjour de 1,8 jours après prothèse totale de hanche — DM −1,8 j ; IC95% −2,3 à −1,3 ; p<0,001 ; RCT, n=420."
  impact_pratique : "En pratique : initier la marche avec aide technique dès J1 post-PTH — coordination avec chirurgien pour lever les restrictions de mise en charge."

Bon exemple 2 :
  resume : "Les exercices de stabilisation lombaire réduisent la douleur chronique de 38 % à 6 mois vs physiothérapie passive — DM EVA −2,1/10 ; IC95% −2,8 à −1,4 ; RCT, n=312."
  impact_pratique : "À retenir : programme de renforcement du gainage 3×/semaine pendant 8 semaines supérieur aux ultrasons ou TENS en lombalgies chroniques — personnaliser la progression."

Bon exemple 3 :
  resume : "La rééducation vestibulaire diminue le risque de chute de 44 % chez les patients avec névrite vestibulaire — RR 0,56 ; IC95% 0,38–0,82 ; p=0,003 ; RCT, n=180, suivi 6 mois."
  impact_pratique : "En pratique : prescrire rééducation vestibulaire dès la phase subaiguë (J7–J14) — exercices de stabilisation du regard et habituation au mouvement, 2 séances/semaine."

"""

_SPECIALTY_ADDENDUM_NEUROLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — NEUROLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : neurologue (CHU / clinique privée / libéral, France), \
prenant en charge : sclérose en plaques (SEP), maladie de Parkinson et \
syndromes parkinsoniens, épilepsie, AVC/AIT, céphalées et migraine, \
maladies neurodégénératives (Alzheimer, DFT, MCL), maladies neuromusculaires \
(SLA, myopathies, neuropathies), neuroimmunologie (NMOSD, MOGAD, encéphalites \
auto-immunes). Référentiels : recommandations EAN (European Academy of Neurology), \
AAN Practice Guidelines, recommandations SFSEP (SEP), ANAES/HAS (AVC, épilepsie), \
recommandations SFN (Société Française de Neurologie).

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur) :
• Sclérose en plaques (SEP-RR) : ocrelizumab (OPERA I/II, ORATORIO) ; \
ofatumumab (ASCLEPIOS I/II) ; ozanimod (SUNBEAM, RADIANCE) ; \
ponesimod (OPTIMUM) ; ublituximab (ULTIMATE I/II) ; \
cladribine (CLARITY, CLARITY-EXT) ; natalizumab (AFFIRM) ; \
alemtuzumab (CARE-MS I/II) ; fenebrutinib/tolebrutinib (BTK inhibiteurs SEP) ; \
recommandations SFSEP 2023 ; haute efficacité précoce vs escalade thérapeutique.
• SEP-SP/PP : siponimod (EXPAND SEP-SP) ; ofatumumab SEP-PP ; \
résultats décevants SEP progressive (INFORMS, OLYMPUS rituximab).
• Parkinson et syndromes parkinsoniens : levodopa/carbidopa, agonistes \
dopaminergiques (pramipexole, rotigotine, ropinirole) ; MAO-B inhibiteurs \
(rasagiline ADAGIO, safinamide) ; amantadine dyskinésies ; \
DBS STN vs GPi (VA-DEST) ; pompe à apomorphine/duodopa ; \
synucleine-targeting (prasinezumab — PASADENA) ; GDNF gene therapy.
• AVC ischémique : NINDS (altéplase IV <3h) ; ECASS-3 (altéplase 3-4,5h) ; \
DAWN/DEFUSE-3 (thrombectomie mécanique jusqu'à 24h) ; \
ARUBA/COSS (MAV/occlusion carotide) ; CHANCE-2 (ticagrélor + aspirine AIT/AVC mineur \
porteurs CYP2C19 LOF) ; SAMMPRIS (stenting intracrânien) ; \
POINT/CHANCE (double antiplaquettaire précoce AIT) ; \
hémorragie cérébrale : TICH-2 (TXA), INTERACT-2/ATACH-2 (contrôle TA).
• Épilepsie : brivaracétam, perampanel, lacosamide, cenobamate \
(X-TOLE — épilepsie partielle réfractaire) ; SANAD II (lamotrigine vs \
levetiracétam vs valproate APC focale/généralisée) ; recommandations EAN 2022 \
(monothérapie 1ère intention, anti-NMDA épilepsie auto-immune) ; \
chirurgie épilepsie (ILAE guidelines) ; SUDEP prévention.
• Migraine : gepants (ubrogepant, rimegepant, atogepant) anti-CGRP aigus ; \
anti-CGRP préventifs (erenumab ARISE/STRIVE, fremanezumab HALO, \
galcanezumab EVOLVE/REGAIN, eptinezumab PROMISE) ; \
lasmiditan (SAMURAI, SPARTAN) ; recommandations EHF/IHS 2023.
• Maladies neurodégénératives / Alzheimer : lecanemab (CLARITY AD) — \
approbation FDA accélérée 2023 ; donanemab (TRAILBLAZER-ALZ-2) ; \
aducanumab (ENGAGE/EMERGE — controversé) ; tau-targeting ; \
critères AT(N) biomarqueurs LCR/PET-amyloïde/PET-tau.
• Maladies neuromusculaires : nusinersen (ENDEAR, CHERISH) SMA ; \
risdiplam (FIREFISH, SUNFISH) SMA oral ; onasemnogène abeparvovec (SMA-1) ; \
tofersen (VALOR/OLE — SOD1 SLA antisens) ; riluzole/edaravone SLA ; \
ravulizumab/eculizumab NMOSD AQP4+ ; inebilizumab (N-MOMENTUM NMOSD) ; \
satralizumab (SAkuraStar/SAkuraSky NMOSD).

CRITÈRE DE PERTINENCE NEUROLOGIE :
"Ce résultat va-t-il modifier le choix d'un traitement de fond, \
une décision de mise sous traitement ou de changement de ligne \
thérapeutique pour un patient neurologique suivi en France ?" \
Rejeter : études fondamentales sans endpoint clinique, biomarqueurs \
exploratoires non validés en pratique courante, résultats de phase 2 \
sans implication immédiate, confirmations de pratiques déjà établies.

SCORES :
• Score 8-9 : essai pivot ou guideline EAN/AAN modifiant un standard \
thérapeutique majeur (nouveau traitement de fond SEP haute efficacité, \
extension de fenêtre thérapeutique AVC, nouvel antiépileptique changeant \
l'algorithme, anti-CGRP préventif) ; nouveau biomarqueur cliniquement validé \
(neurofilaments NfL plasma).
• Score 6-7 : RCT ≥100 patients avec endpoint fonctionnel validé (EDSS, \
UPDRS, mRS, réduction crises) nuançant une pratique établie, méta-analyse \
sur choix de traitement en épilepsie ou Parkinson, nouvelle molécule en \
phase 3 prometteuse mais non encore approuvée.
• Score ≤5 (exclure) : études biomarqueurs <50 patients, études \
neuroimagerie sans corrélat clinique, confirmations de pratiques intégrées \
dans les guidelines actuels.
• Contexte FRANÇAIS : disponibilité et remboursement en France \
(anticorps monoclonaux SEP/migraine, onabotulinumtoxinA migraine, \
RTU/AAP/ATU si pertinent), réseau filières AVC/SEP/Parkinson, \
recommandations HAS/SFSEP/SFN."

EXEMPLES DE RÉDACTION (style Lancet Neurology / Neurology / Brain / JNNP — format cible) :

SEP-RR — traitement haute efficacité :
  titre_court : "ULTIMATE I/II : ublituximab −59 % taux annualisé de rechutes vs tériflunomide"
  resume : "ULTIMATE I+II pooled (RCT, N=1 094, SEP-RR, 96 semaines) : ublituximab 450 mg IV \
q24 sem vs tériflunomide 14 mg — TAR 0,08 vs 0,19 (réduction 59 % ; RR 0,41 ; \
IC95% 0,30–0,57 ; p<0,001). Lésions T2 nouvelles −97 %. Réactions perfusion grade 1-2 \
à la 1re administration dans 47 %."
  impact_pratique : "À retenir : ublituximab s'ajoute aux anti-CD20 disponibles en SEP-RR active — \
choisir selon profil CV, parité planifiée et accès centre pour perfusion."

AVC ischémique — thrombectomie tardive :
  titre_court : "DAWN : thrombectomie jusqu'à 24h — mRS 0-2 à 90j : 49 % vs 13 %"
  resume : "DAWN (RCT, N=206, NIHSS ≥10, occlusion ACM/ACI, 6-24h, mismatch clinico-imagerie) : \
thrombectomie mécanique vs médical seul — indépendance (mRS 0-2) à 90j : 49 % vs 13 % \
(OR 4,34 ; IC95% 2,33–8,10 ; p<0,001). Intégré guidelines AAN/ESO ; protocole RAPID ou \
équivalent requis."
  impact_pratique : "En pratique : tout AVC avec occlusion proximale au-delà de 6h doit bénéficier \
d'une imagerie de perfusion — appel direct au centre thrombectomie, pas d'attente."

Migraine — anti-CGRP remboursé :
  titre_court : "Erenumab migraine épisodique fréquente : −2,9 j/mois, remboursé SS France"
  resume : "ARISE (RCT, N=577, 4-14 jours de migraine/mois) : erenumab 70 mg SC vs placebo — \
réduction jours migraine −2,9 vs −1,8/mois (différence −1,1 ; p<0,001) ; \
répondeurs ≥50 % : 40 % vs 30 %. Remboursé SS France depuis 2021 \
(≥8 jours/mois ou migraine chronique, après 2 échecs de préventifs classiques)."
  impact_pratique : "En pratique : proposer après échec topiramate + propranolol — \
prescription initialement hospitalière (neurologie), puis renouvellement possible en ville."

## EXEMPLES DE RÉDACTION
Style de référence : Lancet Neurology, Neurology (AAN), NEJM (neurologie), Journal of Neurology Neurosurgery & Psychiatry.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "La thrombectomie mécanique réduit le handicap fonctionnel à 90 jours de 19 points absolus dans les occlusions de grand vaisseaux — OR 2,35 ; IC95% 1,85–3,00 ; méta-analyse 5 RCTs, n=1 287."
  impact_pratique : "En pratique : activer la filière thrombectomie pour tout AVC ischémique avec occlusion ICA/M1/M2 dans les 24 h — score NIHSS ≥6, pas de seuil d'âge strict."

Bon exemple 2 :
  resume : "Le natalizumab réduit le taux annualisé de rechutes de 68 % dans la SEP récurrente-rémittente active — RR 0,32 ; IC95% 0,25–0,41 ; p<0,001 ; AFFIRM, RCT, n=942, 2 ans."
  impact_pratique : "À retenir : natalizumab en 2e ligne SEP active malgré interféron/acétate de glatiramère — vérifier sérologie JC avant initiation et à 6 mois."

Bon exemple 3 :
  resume : "La stimulation cérébrale profonde du GPi améliore le score moteur UPDRS-III de 52 % à 12 mois dans la maladie de Parkinson avancée — DM −20,4 points ; IC95% −25,1 à −15,7 ; RCT, n=255."
  impact_pratique : "En pratique : orienter vers évaluation SCP les patients Parkinson avec fluctuations motrices invalidantes malgré optimisation médicamenteuse — fenêtre idéale avant déclin cognitif."

"""

_SPECIALTY_ADDENDUM_NEUROCHIRURGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — NEUROCHIRURGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : neurochirurgien (CHU / clinique privée, France), \
prenant en charge : neuro-oncologie (gliomes, méningiomes, métastases \
cérébrales, tumeurs hypophysaires), neurochirurgie vasculaire (anévrismes \
intracrâniens, MAV, cavernomes, hemorragies sous-arachnoïdiennes HSA), \
chirurgie rachidienne (sténose lombaire, hernie discale, tumeurs rachidiennes, \
déformations), neurochirurgie fonctionnelle (DBS, stimulation médullaire, \
chirurgie épilepsie, radiochirurgie gamma-knife), traumatologie crânio-rachidienne, \
neurochirurgie pédiatrique (hydrocéphalie, craniosynostoses). \
Référentiels : AANS/CNS guidelines, EANS recommendations, SNO guidelines \
(tumeurs cérébrales), BTF guidelines (traumatisme crânien sévère), \
recommandations SNCLF/SFNC (Société Française de Neurochirurgie).

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur) :
• Glioblastome (GBM) : EORTC-22981/26981 (Stupp — temozolomide + RT \
standard of care) ; EF-14 (TTFields / Optune + TMZ) ; CATNON (TMZ RT-IDH1 \
non codelé) ; essais IDH inhibiteurs (ivosidenib INDIGO — IDH1 astrocytome \
de grade 2-3) ; vorasidenib (INDIGO IDH1/2 gliome bas grade) ; \
MGMT (méthylation — prédicteur réponse TMZ) ; TERT/EGFR/CDKN2A.
• Méningiomes : chirurgie (score Simpson) + surveillance ; radiochirurgie \
(gamma knife GKRS) méningiomes grade 1 <3 cm, sinus caverneux ; \
méningiomes grade 2/3 : RT adjuvante (RTOG 0539/NRG BN003).
• Métastases cérébrales : SRS (radiosurgery) vs chirurgie ; WBRT vs SRS \
(QUARTZ) ; anti-PD1 cérébral (melanome, NSCLC) ; DESTINY-Lung04 \
(T-DXd métastases HER2) ; association SRS + immunothérapie.
• Anévrismes intracrâniens : ISAT (coiling vs clipping anévrisme rompu) ; \
ISUIA (prévalence et risque rupture anévrismes non rompus) ; \
flow-diverters (Pipeline) anévrismes non rompus large/giant ; \
HSA / vasosoarme (CONSCIOUS-3 clazosentan).
• Neurochirurgie rachidienne : SPORT (hernie discale, sténose lombaire) ; \
ACDF vs prothèse discale cervicale (PRESTIGE, ProDisc-C) ; \
laminoplastie vs laminectomie myélopathie cervicale ; \
cimentoplastie vertébrale (VERTOS IV) ; TLIF/LLIF vs PLIF.
• Neurochirurgie fonctionnelle : DBS thalamus/GPi/NST \
(Parkinson, tremblement essentiel, dystonie) ; \
SANTE trial (DBS ANT épilepsie) ; gamma-knife névralgie trijumeau ; \
chirurgie résective épilepsie (résection temporale mésiale) ; \
SEEG (stéréo-EEG).
• Traumatisme crânien : BTF guidelines 4th edition 2016 (PIC, \
craniectomie décompressive DECRA/RESCUEicp) ; CRASH-3 (TXA TC modéré-sévère) ; \
IMPACT prognostic score.
• Neurochirurgie pédiatrique : hydrocéphalie (dérivation VP vs ETV/CPC) ; \
ETV score ETVSS ; médulloblastome (chirurgie + RT + CT selon groupe de risque).

CRITÈRE DE PERTINENCE NEUROCHIRURGIE :
"Ce résultat va-t-il modifier l'indication opératoire, le choix de technique \
chirurgicale, le protocole adjuvant (RT/CT) ou la surveillance d'une pathologie \
neurochirurgicale en France ?" \
Rejeter : études fondamentales, résultats in vitro/animaux, études \
radiologiques sans corrélat chirurgical, séries de cas < 20 patients \
sans endpoint fonctionnel validé.

SCORES :
• Score 8-9 : essai pivot modifiant un standard en neuro-oncologie \
(survie GBM, nouveaux agents IDH), nouvelle technique invasive validée \
en phase 3 (DBS nouvelle cible, flow-diverter), guideline AANS/CNS/SNO \
de grade A modifiant la pratique.
• Score 6-7 : RCT ou méta-analyse ≥100 patients apportant un résultat \
nouveau sur une technique chirurgicale (rachis, vasculaire, tumeurs), \
validation d'un score pronostique ou d'un biomarqueur moléculaire \
(MGMT, IDH, TERT) en pratique courante.
• Score ≤5 (exclure) : séries rétrospectives monocentriques <50 patients, \
études techniques sans comparateur actif, résultats confirmant des pratiques \
déjà établies sans information nouvelle.
• Contexte FRANÇAIS : accessibilité France (AMM TTFields, disponibilité \
ivosidenib/vorasidenib, financement MIGAC/INCa), réseau neuro-oncologique \
(RCP nationale INCa) ; recommandations SNCLF/HAS."

EXEMPLES DE RÉDACTION (style Journal of Neurosurgery / Neurosurgery / Acta Neurochirurgica — format cible) :

Glioblastome — traitement adjuvant :
  titre_court : "EF-14 (TTFields + TMZ) : +4,9 mois survie globale vs TMZ seul en GBM"
  resume : "EF-14 (RCT, N=695, GBM nouvelle souche après chimioradiation, MGMT méthylé ou non) : \
TTFields (Optune 200 kHz) + témozolomide vs témozolomide seul — SG 20,9 vs 16,0 mois \
(HR 0,63 ; IC95% 0,53–0,76 ; p<0,001) ; SSP 6,7 vs 4,0 mois. Compliance TTFields : \
>18h/j corrélée à meilleur pronostic. AMM CE obtenue, remboursement France en cours \
(MIGAC-INCa)."
  impact_pratique : "En pratique : TTFields à discuter en RCP pour tout GBM post-chimioradiation — \
vérifier le remboursement actuel et orienter vers centre INCa référent."

Métastases cérébrales — radiochirurgie vs chirurgie :
  titre_court : "SRS vs chirurgie métastase cérébrale unique ≤3 cm : contrôle local équivalent"
  resume : "Revue systématique ASTRO (N=1 827, 12 études, métastase unique ≤3 cm accessible) : \
SRS vs résection chirurgicale — contrôle local à 1 an 73 % vs 78 % (RR 1,06 ; \
IC95% 0,95–1,19 ; p=0,31) ; pas de différence SG. SRS associée à moins de complications \
post-procédure (8 % vs 22 %). Chirurgie préférée si masse effet et/ou diagnostic histologique requis."
  impact_pratique : "En pratique : SRS privilégiée pour métastase unique ≤3 cm sans effet de masse \
significatif — discussion RCP multidisciplinaire neuro-onco systématique."

Hémorragie sous-arachnoïdienne — vasospasme :
  titre_court : "Nimodipine HSA : réduction vasospasme symptomatique confirmée — dose orale = IV"
  resume : "Méta-analyse (N=4 152, 9 RCTs, HSA anévrismale) : nimodipine 60 mg/4h PO pendant \
21 jours — réduction vasospasme symptomatique 34 % vs placebo (RR 0,66 ; IC95% 0,59–0,75) ; \
bénéfice neurologique (mRS 0-2) à 3 mois. Formulation IV non disponible en France ; \
voie orale strictement équivalente si patient neurologique stable."
  impact_pratique : "À retenir : nimodipine orale 60 mg/4h pendant 21 jours — standard non négociable \
dans toute HSA anévrismale ; surveillance tensionnelle à chaque prise."

## EXEMPLES DE RÉDACTION
Style de référence : Journal of Neurosurgery, Neurosurgery, Acta Neurochirurgica, Journal of Neuro-Oncology.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "La résection étendue guidée par fluorescence (5-ALA) améliore la survie globale médiane de 4,5 mois dans les glioblastomes — 18,3 vs 13,8 mois ; HR 0,73 ; IC95% 0,57–0,94 ; RCT, n=322."
  impact_pratique : "En pratique : utiliser systématiquement la 5-ALA pour les résections de glioblastome opérable — augmentation du taux de résection complète sans augmentation des déficits."

Bon exemple 2 :
  resume : "La radiochirurgie stéréotaxique (Gamma Knife) est non-inférieure à la microchirurgie pour les méningiomes de la base grade I ≤3 cm — contrôle tumoral à 10 ans 94 % vs 97 % ; HR 1,12 ; IC95% 0,74–1,71 ; cohorte prospective, n=892."
  impact_pratique : "À retenir : proposer radiochirurgie en 1re intention pour méningiomes de la base <3 cm asymptomatiques — évite les risques opératoires sans compromettre le contrôle local."

Bon exemple 3 :
  resume : "Le clippage précoce (<24 h) réduit le risque de resaignement de 67 % après hémorragie sous-arachnoïdienne anévrismale — RR 0,33 ; IC95% 0,18–0,61 ; méta-analyse, n=3 840."
  impact_pratique : "En pratique : clippage ou coiling dans les 24 h pour tout anévrisme rompu accessible — discuter en réunion neurovasculaire urgente dès admission."

"""

_SPECIALTY_ADDENDUM_NEPHROLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — NÉPHROLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : néphrologue (CHU / CH / centre de dialyse / consultation \
privée, France), prenant en charge : maladie rénale chronique (MRC stades 1-5), \
glomérulonéphrites (néphrotique, néphritique), néphropathies diabétiques, \
hypertension artérielle rénovasculaire, troubles hydroélectrolytiques, \
dialyse (hémodialyse, dialyse péritonéale), transplantation rénale. \
Référentiels : KDIGO guidelines 2022-2024 (CKD, GN, AKI, DM), \
recommandations ERA (ERBP), SFNDT (Société Francophone de Néphrologie \
Dialyse et Transplantation), recommandations HAS transplantation.

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur) :
• MRC / protection rénale : DAPA-CKD (dapagliflozine MRC stades 2-4, \
diabète ou non) ; CREDENCE (canagliflozine DKD) ; FIDELIO-DKD / \
FIGARO-DKD (finérénone — antagoniste non stéroïdien MR, DKD T2) ; \
EMPA-KIDNEY (empagliflozine MRC élargie) — iSGLT2 en première ligne MRC ; \
RENAAL/IDNT/IRMA-2 (sartans — DKD type 2, standard de référence) ; \
SPRINT (contrôle tensionnel intensif <120 mmHg) ; ALTITUDE (aliskiren \
double blocage SRA — négatif, abandonné).
• Glomérulonéphrites : TESTING 2 (méthylprednisolone IV nephropathie à IgA) ; \
PROTECT (sparsentan — GN IgA) ; DUPLEX (sparsentan FSGS) ; \
rituximab (GEMRITUX, MENTOR) syndrome néphrotique idiopathique cortico-dépendant \
et FSGS ; voclosporine + MMF (lupus néphrite) ; avacopan (ADVOCATE) vascularite ANCA.
• AKI : KDIGO AKI guidelines 2012 (classification AKIN/RIFLE→KDIGO) ; \
STARRT-AKI (épuration extra-rénale précoce vs tardive) ; AKIKI-2 (stratégie \
très tardive EER) ; furosémide forte dose ; prévention néphrotoxicité \
produits de contraste (hydratation, arrêt IEC).
• Dialyse hémodialyse : ESHD (flux convectif hémofiltration en ligne HDF vs HD) ; \
fréquence dialyse (HEMO study, FHN nocturne) ; membranes haute perméabilité ; \
cathéters tunnelisés vs FAV (KoMO-study) ; calcimimétiques (cinacalcet EVOLVE) ; \
EPO/ASE (TREAT, CREATE — cible Hb 10-11 g/dL) ; DOPPS registry.
• Dialyse péritonéale : ISPD guidelines 2022 (péritonites, adéquation) ; \
DP automatisée APD vs DPCA ; biocompatibles solutions neutres pH.
• Transplantation rénale : belatacept (BENEFIT) vs ciclosporine ; \
évérolimus (ASCERTAIN) + réduction CNI ; induction (basiliximab vs \
anti-thymocytes) ; désensibilisation (rituximab, éculizumab, Bortézomib) ; \
rejet humoral (DSA, C4d) — recommandations HAS/SFNDT 2018 ; \
ticagrélor thrombose vasculaire transplant ; immunosuppression (tacrolimus \
niveaux résiduels 5-8 ng/mL à 1 an) ; dépistage CMV/BKV post-transplant.
• Troubles hydroélectrolytiques : hyponatrémie (SALT-1/SALT-2 tolvaptan SIADH) ; \
hyperkaliémie : patiromer (OPAL-HK) et sodium zirconium cyclosilicate \
(ZS-9 / HARMONIZE) — AMM EU 2015/2018.

CRITÈRE DE PERTINENCE NÉPHROLOGIE :
"Ce résultat va-t-il modifier la prescription d'un néphroprotecteur, \
le protocole de dialyse, le suivi d'une glomérulopathie ou l'immunosuppression \
d'un transplanté rénal en France ?" \
Rejeter : études fondamentales sans endpoint clinique validé, résultats \
uniquement en modèle murin ou cellulaire, épidémiologie sans implication \
thérapeutique, confirmations de pratiques KDIGO déjà intégrées.

SCORES :
• Score 8-9 : essai pivot ou guidelines KDIGO/ERA/SFNDT modifiant un standard \
thérapeutique (nouveau néphroprotecteur, protocole dialyse, induction transplant) ; \
nouveau guideline KDIGO avec recommandations de grade 1A-1B.
• Score 6-7 : RCT ≥100 patients ou méta-analyse modifiant le suivi d'une \
glomérulopathie, d'un transplanté ou d'un dialysé ; validation d'un biomarqueur \
(NGAL, KIM-1) en pratique clinique.
• Score ≤5 (exclure) : études rétrospectives <50 patients, études sur \
des biomarqueurs expérimentaux sans application clinique immédiate.
• Contexte FRANÇAIS : disponibilité AMM en France (patiromer, sparsentan non \
encore remboursés), réseau REIN (registre dialyse/greffe France), \
SFNDT recommandations, HAS avis remboursement."

EXEMPLES DE RÉDACTION (style JASN / Kidney International / NDT / CJASN — format cible) :

Néphroprotection diabétique :
  titre_court : "DAPA-CKD : dapagliflozine réduit de 39 % la progression rénale en MRC non diabétique"
  resume : "DAPA-CKD (RCT, N=4 304, MRC stades 2-4 avec albuminurie, dont 32 % non-diabétiques) : \
dapagliflozine 10 mg/j vs placebo — réduction composite rénale (−40 % eGFR, dialyse, \
décès rénal/CV) de 39 % (HR 0,61 ; IC95% 0,51–0,72 ; p<0,001). Bénéfice confirmé \
chez non-diabétiques (HR 0,50). AMM EMA étendue à la MRC sans diabète."
  impact_pratique : "En pratique : dapagliflozine à proposer dans toute MRC avec DFG 25-75 mL/min \
et albuminurie ≥200 mg/g, diabétique ou non — vérifier le remboursement actuel en France."

Greffe rénale — immunosuppression :
  titre_court : "Belatacept vs ciclosporine greffe rein : survie greffon +13 % à 7 ans"
  resume : "BENEFIT extended (RCT, N=666, greffe rein donneur vivant/décédé à critères standard, \
7 ans) : belatacept vs ciclosporine — survie patient-greffon 80 % vs 67 % (HR 0,57 ; \
IC95% 0,40–0,83). DFG moyen +21 mL/min vs ciclosporine. Risque PTLD légèrement majoré \
(EBV-naïfs exclus si possible)."
  impact_pratique : "À retenir : belatacept confère une meilleure fonction rénale à long terme \
que la ciclosporine — à discuter en RCP pour les greffes à risque de néphrotoxicité."

Hyperkaliémie chronique — IRC :
  titre_court : "Patiromer : maintien des inhibiteurs SRAA possible malgré hyperkaliémie chronique"
  resume : "DIAMOND (RCT croisée, N=160, ICC ou MRC avec hyperkaliémie, traité IEC/ARA2) : \
patiromer vs placebo — kaliémie moyenne 4,7 vs 5,2 mmol/L (différence −0,45 ; p<0,001). \
Maintien de la dose maximale de spironolactone dans 66 % vs 43 % des cas (p=0,006). \
Disponible en France, non remboursé à ce jour."
  impact_pratique : "En pratique : patiromer permet de maintenir les inhibiteurs SRAA chez \
les IRC/ICC hyperkaliémiques — discuter avec néphrologue et vérifier accès en France."

## EXEMPLES DE RÉDACTION
Style de référence : JASN (Journal of the American Society of Nephrology), CJASN, NDT (Nephrology Dialysis Transplantation), KI (Kidney International).
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "Les iSGLT2 réduisent la progression vers l'insuffisance rénale terminale de 34 % dans la néphropathie diabétique — HR 0,66 ; IC95% 0,53–0,81 ; p<0,001 ; CREDENCE, RCT, n=4 401, suivi 2,6 ans."
  impact_pratique : "En pratique : initier canagliflozine/dapagliflozine chez tout DT2 avec néphropathie et DFGe ≥20 mL/min — surveillance kaliémie et DFGe à 4 semaines."

Bon exemple 2 :
  resume : "La fistule artério-veineuse réduit la mortalité cardiovasculaire de 28 % vs cathéter central tunnellisé en hémodialyse — HR 0,72 ; IC95% 0,61–0,85 ; cohorte, n=12 400, suivi 3 ans."
  impact_pratique : "À retenir : créer la FAV au moins 6 mois avant la dialyse prévisible — référence chirurgie vasculaire dès DFGe <20 mL/min chez les patients sans contre-indication."

Bon exemple 3 :
  resume : "L'avacopan remplace les corticoïdes en phase d'induction et réduit les rechutes de 40 % dans les vascularites ANCA — OR 0,60 ; IC95% 0,38–0,95 ; p=0,03 ; ADVOCATE, RCT, n=331."
  impact_pratique : "En pratique : avacopan (300 mg × 2/j) + rituximab ou cyclophosphamide permet d'épargner les corticoïdes systémiques — à privilégier si diabète cortico-induit ou ostéoporose sévère."

"""

_SPECIALTY_ADDENDUM_URGENCES = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — MÉDECINE D'URGENCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : médecin urgentiste (SAU / SAMU-SMUR / UHCD, France), \
prenant en charge toutes pathologies aiguës : arrêt cardiaque, syndromes \
coronariens aigus, AVC, sepsis/choc septique, traumatismes, intoxications, \
détresse respiratoire, urgences neurologiques, obstétricales, pédiatriques. \
Référentiels : guidelines ERC/AHA 2021 réanimation cardiopulmonaire, \
Surviving Sepsis Campaign 2021, recommandations SFMU (Société Française \
de Médecine d'Urgence), SAMU de France, EUSEM guidelines.

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur) :
• Arrêt cardiaque : ERC/AHA guidelines 2021 (RCP haute qualité, DEA précoce, \
hypothermie thérapeutique TTM2 — abandon protocole 33°C, ROC/ALPS lidocaïne \
vs amiodarone) ; PARAMEDIC2 (adrénaline vs placebo ACR OHCA) ; \
compressions thoraciques mécaniques (LINC, PARAMEDIC, CIRC) ; \
ECMO-RCP (ARREST, PRAGUE-OHCA) extracorporeal CPR.
• Sepsis / choc septique : SSC bundle 2021 (antibiotiques 1h, lactate, \
prélèvements, vasopresseurs si PAM<65) ; SMART (Ringer lactate vs sérum \
physiologique cristalloïdes) ; ANDROMEDA-SHOCK (réévaluation capillaire \
vs lactate) ; CLOVERS/CLASSIC (stratégie restrictive remplissage) ; \
procalcitonine pour désescalade antibiotique.
• Analgésie/sédation : protocole 3x3 douleur SFMU ; kétamine faible dose \
(Sub-dissociative ketamine) ; PAIN-FREE (morphine vs kétamine douleur modérée-sévère) ; \
méthoxyflurane ; infiltrations locorégionales (fascia iliaca, TAP block) \
aux urgences.
• Traumatologie / damage control : CRASH-2 (acide tranexamique <3h traumatisme \
hémorragique) ; TARN/MTC (Major Trauma Centre) ; protocole massive transfusion \
ratio 1:1:1 (CGR:PFC:plaquettes) ; tourniquet militaire en civil.
• AVC/AIT : DAWN/DEFUSE-3 (thrombectomie étendue jusqu'à 24h) ; \
ENCHANTED (altéplase faible dose) ; tenectéplase vs altéplase thrombolyse \
(NOR-TEST, ATTEST-2) ; CHANCE/CHANCE-2 (dual antiplaquettaire AIT/AVC mineur).
• Dyspnée / IRA : VNI/CPAP (3CPO, FLORALI) ; VNI vs oxygène haut débit \
(OPTIFLOW/Thrive) ; FRESH-AIR (air ambiant vs O₂ BPCO) ; \
algorithme SAMU bronchospasme/OAP.
• Intoxications : charbon actif (délai <1h, dose unique) ; antidotes \
(naloxone opioïdes, flumazénil BZD, N-acétylcystéine paracétamol, \
diazépam organophosphorés) ; hydroxocobalamine intox CO/cyanure.
• Outils décision : HEART score (douleur thoracique) ; Ottawa knee/ankle rules \
(traumatologie) ; Wells/YEARS (EP/TVP) ; ABCD2 score (AIT) ; \
triage Manchester (MTS) ; scores NEWS2/qSOFA.

CRITÈRE DE PERTINENCE URGENCES :
"Ce résultat va-t-il modifier une décision de prise en charge immédiate, \
un protocole de réanimation ou un algorithme décisionnel aux urgences \
ou au SAMU/SMUR en France ?" \
Rejeter : études épidémiologiques sans impact sur la prise en charge aiguë, \
résultats de réanimation en ICU sans pertinence en porte (tri ou déclenchement), \
recherche fondamentale, études en milieu non-urgentiste.

SCORES :
• Score 8-9 : essai pivot ou guidelines ERC/AHA/SFMU/SSC modifiant un \
protocole de réanimation standard (RCP, sepsis, trauma, AVC) ou validant \
un outil de triage/décision à fort impact pratique immédiat.
• Score 6-7 : RCT ≥100 patients sur une thérapeutique aiguë, méta-analyse \
modifiant le choix d'une analgésie, d'un vasopresseur ou d'une stratégie \
de remplissage, validation prospective d'un score décisionnel.
• Score ≤5 (exclure) : études rétrospectives <50 patients, études dans \
des populations non représentatives des SAU français, confirmations de \
pratiques déjà établies.
• Contexte FRANÇAIS : disponibilité en France (AMM, accès SAU, \
protocoles SAMU), réglementation CRRA-15/SMUR, financement MERRI/UHCD."

EXEMPLES DE RÉDACTION (style Annals of Emergency Medicine / Resuscitation / Academic Emergency Medicine — format cible) :

Arrêt cardiaque extrahospitalier :
  titre_court : "ECMO-RCP (ECPR) : survie à bon pronostic neurologique × 2 vs RCP conventionnelle"
  resume : "ARREST (RCT, N=30, AC réfractaire OHCA FV/TV sans pouls, arrêt <45 min, CAG accès <60 min) : \
ECPR vs traitement standard — survie à la sortie avec CPC 1-2 : 43 % vs 7 % (OR 9,4 ; \
IC95% 2,0–44,1 ; p=0,006). Étude stoppée prématurément. Population très sélectionnée \
(jeune, témoin, rythme choquable)."
  impact_pratique : "En pratique : ECPR à discuter en RCP réfractaire FV/TV avec équipe \
spécialisée disponible — critères stricts (âge, délai, rythme) ; hors ces critères, \
pas d'indication."

Sepsis aux urgences :
  titre_court : "SSC 2021 : antibiotiques dans l'heure — bénéfice confirmé si lactate ≥ 2"
  resume : "Surviving Sepsis Campaign 2021 (recommandations actualisées) : antibiothérapie \
dans l'heure recommandée (Grade 1B) pour sepsis avec lactate ≥ 4 mmol/L ou choc septique. \
Antibiotiques dans les 3h si lactate 2-4 mmol/L sans choc. Chaque heure de retard associée \
à +7% mortalité (étude observationnelle, N=49 331, IDSA/SCCM)."
  impact_pratique : "En pratique : prélèvements hémocultures et administration simultanée — \
ne pas retarder les antibiotiques en attendant les résultats microbiologiques si choc ou \
lactate ≥ 4."

Analgésie aux urgences :
  titre_court : "Kétamine faible dose vs morphine douleur aiguë : efficacité équivalente, moins d'effets"
  resume : "PAIN-FREE (RCT multicentrique, N=312, douleur EVA ≥ 5 aux urgences) : kétamine \
sub-dissociative (0,3 mg/kg IV) vs morphine (0,1 mg/kg IV) — réduction EVA à 30 min : \
−2,9 vs −2,8 points (différence 0,1 ; IC95% −0,6–0,8 ; non-inférieur). Nausées-vomissements : \
9 % vs 22 % (p=0,003). Pas de différence sécurité."
  impact_pratique : "En pratique : kétamine 0,3 mg/kg IV alternative valide à la morphine \
pour douleurs aiguës modérées-sévères — privilégier si risque d'emesis ou contre-indication \
aux opioïdes."

## EXEMPLES DE RÉDACTION
Style de référence : Annals of Emergency Medicine, Emergency Medicine Journal, Resuscitation, Academic Emergency Medicine.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "Le score HEART ≤3 permet d'exclure un STEMI/NSTEMI avec une valeur prédictive négative de 99,3 % en douleur thoracique aiguë — sensibilité 98 % ; RCT validationn, n=3 582, 30 centres."
  impact_pratique : "En pratique : utiliser HEART + troponine hs à H0/H2 pour les douleurs thoraciques à bas risque — sortie possible à H2 si HEART ≤3 + troponine négative × 2."

Bon exemple 2 :
  resume : "Le kétamine IV à faible dose (0,3 mg/kg) est non-inférieure à la morphine pour l'analgésie des douleurs aiguës modérées-sévères aux urgences — EVA −3,4 vs −3,7 ; DM 0,3 ; IC95% −0,2 à 0,8 ; RCT, n=240."
  impact_pratique : "À retenir : kétamine sub-dissociative alternative à la morphine en 1re ligne douleur aiguë — moins d'effets secondaires respiratoires, utile si dépendance opioïdes connue."

Bon exemple 3 :
  resume : "L'hypothermie thérapeutique post-ACR réduit la mortalité hospitalière de 23 % et améliore le pronostic neurologique — OR 0,77 ; IC95% 0,62–0,96 ; méta-analyse, 12 RCTs, n=3 219."
  impact_pratique : "En pratique : initier refroidissement actif à 33°C dès RACS pour tout ACR extra-hospitalier FV/TV sans réveil immédiat — coordination SAMU/réa avant admission."

"""

_SPECIALTY_ADDENDUM_MPR = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — MÉDECINE PHYSIQUE ET DE RÉADAPTATION (MPR)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : médecin spécialiste en MPR (CHU / SSR / ESSR, France), \
prenant en charge la rééducation fonctionnelle de patients adultes après : \
AVC (rééducation motrice et cognitive, spasticité), traumatisme crânien (TCC), \
lésion médullaire (SCI — paraplégie/tétraplégie), sclérose en plaques (SEP), \
douleurs chroniques (CETD, douleurs neuropathiques, SDRC), amputations, \
pathologies neuromusculaires, réhabilitation oncologique. \
Référentiels : recommandations SOFMER (Société Française de MPR), \
ESPRM guidelines, ISNCSCI pour classification SCI, NIHSS/mRS post-AVC, \
ASIA impairment scale, critères de Budapest SDRC, recommandations SFETD douleur.

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur) :
• Rééducation post-AVC : EXCITE (CIMT — thérapie par contrainte induite), \
tDCS/TMS répétitive (rTMS) récupération motrice post-AVC (recommandations \
HAS 2012 rééducation AVC) ; GRASP (GRASP graded repetitive arm supplementary \
programme) ; FES (functional electrical stimulation) pied tombant ; \
robotique (Lokomat, Armeo, LOPES) — méta-analyses 2020-2024.
• Traumatisme crânien (TCC) : TRACK-TBI (biomarqueurs GFAP/UCH-L1 prédiction \
pronostic TCC) ; recommandations Brain Trauma Foundation 2023 ; \
réhabilitation cognitive (attention, mémoire de travail) — télérééducation.
• Lésion médullaire (SCI) : SCIM III (Spinal Cord Independence Measure) ; \
stimulation électrique épidurale (STIMO, Louisville — récupération motrice \
AIS B/C partielle) ; fampridine (ENERGIZE) marche SEP/SCI ; \
Zephyr stimulateur diaphragmatique ; recommandations ISCoS/EAU SCI neurogène.
• Spasticité : toxine botulinique type A (onabotulinumtoxinA DYSPORT, \
BOTOX ; abobotulinumtoxinA) — recommandations SOFMER/SFMR spasticité 2022, \
protocoles injections écho-guidées ; baclofène intrathécal (ITB — PIP protocole) ; \
tizanidine, dantrolène.
• Sclérose en plaques (SEP) : siponimod, ozanimod, ponesimod dans SEP-SP ; \
ocrelizumab (ORATORIO, OPERA), ofatumumab (ASCLEPIOS) ; \
progrès en neurorééducation SEP (fatigue, Ashworth, EDSS) ; \
recommandations RMR SEP 2023.
• Douleur chronique / neuropathique : prégabaline, duloxétine (RCP, cibles NRS) ; \
neuromodulation (SCS — spinal cord stimulation ; BURST, HF10) essais SENZA-RCT, \
ACCURATE, COMBO ; TENS (transcutaneous electrical nerve stimulation) ; \
recommandations SFETD 2021 douleurs neuropathiques ; SDRC (syndrome douloureux \
régional complexe) — criteria Budapest, kétamine IV, sympathectomie chimique.
• Réhabilitation oncologique : fatigue cancéreuse (activité physique adaptée APA, \
essais EXCAP) ; lymphœdème secondaire — recommandations lymphœdème SOFMER 2022, \
DLM (drainage lymphatique manuel) ; réhabilitation post-mastectomie.
• Appareillage / prothèses : prothèses myoélectriques membres supérieurs (PROPRIO FOOT) ; \
orthèses releveurs pied tombant (SAFO, WalkAide FES) ; \
orthèses de genou post-LCA.

CRITÈRE DE PERTINENCE MPR :
"Ce résultat va-t-il modifier un protocole de rééducation, le choix d'un \
traitement de la spasticité, d'une technique analgésique ou d'un appareillage \
pour un patient en SSR ou en consultation MPR en France ?" \
Rejeter : études fondamentales (mécanismes cellulaires), épidémiologie \
descriptive sans implication de rééducation, études sur <20 patients sans \
point de comparaison, résultats déjà intégrés dans les protocoles SOFMER actuels.

SCORES :
• Score 8-9 : essai pivot ou guideline SOFMER/ESPRM modifiant un protocole \
de rééducation majeur (AVC, TCC, SCI), nouvelle indication toxine botulinique \
(RCP AMM modifié), nouvelle technique de neuromodulation validée en phase 3.
• Score 6-7 : RCT ≥60 patients sur une technique de rééducation avec outcome \
fonctionnel validé (Barthel, FIM, NIHSS, 6MWT, 10MWT), méta-analyse sur \
traitement de la spasticité, douleur neuropathique, rééducation cognitive.
• Score ≤5 (exclure) : études observationnelles rétrospectives <30 patients, \
études sur des prototypes non commercialisés, résultats biomécanique pur.
• Contexte FRANÇAIS : disponibilité en France (LPPR pour appareillage, \
remboursement SS, autorisation AMM botox par indication), réseau SSR/ESSR, \
nomenclature SOFMER-HAS."

EXEMPLES DE RÉDACTION (style APMR / Journal of Rehabilitation Medicine / Disability & Rehabilitation — format cible) :

Essai rééducation post-AVC :
  titre_court : "Robot membre supérieur post-AVC : pas de supériorité vs rééducation intensive"
  resume : "RATULS (RCT, N=770, AVC <6 semaines) : rééducation robotisée (MIT-Manus) vs \
thérapie conventionnelle intensive — aucune différence sur score ARAT à 3 mois \
(OR 1,15 ; IC95% 0,80–1,65 ; p=0,45). Résultats à 6 mois identiques. \
Bénéfice équivalent si intensité horaire comparable."
  impact_pratique : "À retenir : la robotique MS n'apporte pas de bénéfice additionnel si \
l'intensité de rééducation conventionnelle est identique — arbitrage selon accès local."

Spasticité / toxine botulique post-AVC :
  titre_court : "Botox spasticité bras post-AVC : bénéfice fonctionnel conditionné à la rééducation"
  resume : "Pooled analysis GRADES (N=936, 4 RCTs, abobotulinumtoxinA 500-1000 UI vs placebo) : \
réduction de 1,4 points MAS poignet à 4 semaines (p<0,001) ; bénéfice fonctionnel (GAS) \
uniquement si ≥3 séances de kinésithérapie dans les 4 semaines post-injection."
  impact_pratique : "En pratique : couplage systématique de toute injection botulique à ≥3 séances \
de rééducation dans le mois suivant — sans rééducation, pas de gain fonctionnel démontré."

Recommandation réhabilitation BPCO sévère :
  titre_court : "Réhabilitation respiratoire BPCO sévère : bénéfice maintenu à 2 ans si programme continu"
  resume : "Cochrane meta-analysis (N=3 824, 65 RCTs, BPCO GOLD III-IV) : réhabilitation \
respiratoire vs soins habituels — amélioration 6MWT +44 m (IC95% 38–51), dyspnée MRC −0,8 points, \
maintenu à 24 mois uniquement si programme continu (>1 session/mois après phase initiale)."
  impact_pratique : "En pratique : prescrire un programme de maintien (1 session mensuelle minimum) \
après la phase initiale — l'effet disparaît à 12 mois sans suivi structuré."

## EXEMPLES DE RÉDACTION
Style de référence : Annals of Physical and Rehabilitation Medicine, Archives of Physical Medicine and Rehabilitation, Disability and Rehabilitation.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "La rééducation intensive en MPR réduit la durée de séjour post-AVC de 12 jours tout en améliorant le score de Barthel de 18 points — DM +18 ; IC95% +12 à +24 ; RCT, n=380, 8 centres."
  impact_pratique : "En pratique : orienter vers unité MPR dès J5–J7 post-AVC si patient mobilisable — protocole 4 h/j minimum de thérapies combinées (motrice + cognitive + orthophonie)."

Bon exemple 2 :
  resume : "L'orthèse tibio-pédieuse de marche réduit la consommation énergétique de 18 % et améliore la vitesse de marche de 0,14 m/s dans les paralysies spastiques du membre inférieur — DM +0,14 m/s ; IC95% +0,09 à +0,19 ; méta-analyse, n=620."
  impact_pratique : "À retenir : appareillage tibio-pédieux systématique dès que steppage persistant après 6 semaines de rééducation — évaluer la spasticité avant choix matériau (rigide vs articulé)."

Bon exemple 3 :
  resume : "Les injections de toxine botulique A réduisent la spasticité focale (score Ashworth) de 1,5 point et améliorent la fonction à 12 semaines — DM −1,5 ; IC95% −1,9 à −1,1 ; p<0,001 ; méta-analyse, 28 RCTs, n=2 604."
  impact_pratique : "En pratique : injection toxine botulique A en association avec la rééducation intensive — délai d'action 3–5 jours, répétition possible à 12 semaines si réponse partielle."

"""

_SPECIALTY_ADDENDUM_MEDECINE_INTERNE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — MÉDECINE INTERNE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : interniste (médecin spécialiste en médecine interne, CHU / CH / \
clinique privée, France), prenant en charge des maladies systémiques complexes : \
maladies auto-immunes (lupus, vascularites ANCA, myosites, syndrome de Sjögren, \
sclérodermie, myélodysplasies), maladies inflammatoires multisystémiques, \
amylose (AL/ATTR), sarcoïdose, fièvres récurrentes, pathologies rares. \
Référentiels actuels : recommandations SNFMI (Société Nationale Française de \
Médecine Interne), EFIM guidelines, ACR/EULAR pour les connectivites, \
protocoles nationaux de diagnostic et de soins (PNDS) maladies rares (HAS), \
SCORE2 risque CV, ESC/EULAR guidelines selon organe atteint.

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur) :
• Lupus (LES) : essais voclosporine (AURORA-1/2), belimumab (BLISS-52/76), \
anifrolumab (TULIP-1/2) — indication LES modéré-sévère réfractaire ; \
recommandations EULAR LES 2023 (objectifs thérapeutiques, hydroxychloroquine maintenu \
en fond) ; lupus nephrite (voclosporine + MMF + rituximab).
• Vascularites ANCA (GPA/PAM) : avacopan (ADVOCATE) — alternative prednisone \
dans induction rémission vascularites ANCA ; rituximab vs cyclophosphamide \
(RITUXVAS, RAVE) — standard remission induction GPA ; \
recommandations ACR/EULAR vascularites 2022.
• Myosites inflammatoires (DM/PM/MNAI) : EULAR/ACR criteria 2017 ; \
anticorps MSA/MAA (anti-Jo1, anti-MDA5, anti-TIF1γ, anti-SRP, anti-HMGCR) — \
stratification pronostique ; IVIg (ProDERM trial) dans DM réfractaire.
• Sarcoïdose : recommandations ERS/ATS/JRS/ALAT 2022 (corticoïdes, \
méthotrexate, hydroxychloroquine, biothérapies anti-TNF dans cas réfractaires).
• Amylose : daratumumab + CyBorD (ANDROMEDA) amylose AL ; tafamidis \
(ATTR-ACT) et patisiran/inotersen ATTR héréditaire cardiaque — \
recommandations ESC 2023 amylose cardiaque.
• Syndrome des antiphospholipides (SAPL) : essais rivaroxaban (RAPS, TRAPS) — \
anticoagulation directe non supérieure aux AVK dans thrombose SAPL ; \
HCQ en prévention obstétricale ; recommandations EULAR SAPL 2023.
• Maladies auto-inflammatoires / fièvres récurrentes : anakinra/canakinumab \
dans syndromes CAPS/TRAPS/FCAS ; colchicine péricardite récurrente (COPE, \
CORP, ICAP) ; rilonacept (RHAPSODY) récidives péricardite.
• Maladie de Still : tocilizumab, anakinra, canakinumab dans Still adulte \
réfractaire — recommandations SNFMI 2020.
• Multimorbidité / polypharmacie : STOPP/START v3 2023 (critères de \
déprescription chez le sujet âgé) ; interactions médicamenteuses \
immunosuppresseurs (azathioprine + allopurinol, MTX + cotrimoxazole).
• Diagnostics différentiels complexes : maladies rares (PNDS HAS), fièvres \
prolongées inexpliquées (TEP-TDM 18F-FDG, biopsie ostéomédullaire), \
syndrome d'activation macrophagique (SAM — critères HLH-2004).

CRITÈRE DE PERTINENCE MÉDECINE INTERNE :
"Ce résultat va-t-il modifier la prise en charge d'une maladie systémique, \
auto-immune ou rare, ou affiner un critère diagnostique / pronostique utilisé \
au quotidien en médecine interne en France ?" \
Rejeter : études épidémiologiques sans implication diagnostique ou thérapeutique, \
recherche fondamentale sur mécanismes cellulaires, publications en sous-groupes \
très étroits sans pertinence clinique, lettres/éditoriaux.

SCORES :
• Score 8-9 : essai de phase 3 ou méta-analyse pivot modifiant un standard \
dans une maladie systémique courante (lupus, vascularite, amylose, péricardite) ; \
nouvelle recommandation EULAR/SNFMI/ACR modifiant un algorithme diagnostique ou \
thérapeutique de premier plan.
• Score 6-7 : RCT ou cohorte ≥100 patients apportant une information nouvelle \
sur une pathologie systémique (bénéfice d'un traitement de fond, pronostic d'un \
sous-groupe, valeur d'un biomarqueur MSA/MAA en clinique), revue systématique \
modifiant la pratique sur un point précis.
• Score ≤5 (exclure) : études rétrospectives <50 patients sans comparateur, \
séries de cas descriptives sans impact sur la prise en charge, publications \
dans des maladies rarissimes sans aucune applicabilité.
• Contexte FRANÇAIS : applicabilité aux autorisations AMM en France, \
disponibilité des biothérapies (RTU, ATU/AAP si pertinent), réseau filières \
maladies rares (FRRM), prise en charge ALD."

EXEMPLES DE RÉDACTION (style Medicine / Lancet / JAMA Internal Medicine / Revue de Médecine Interne — format cible) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Lupus systémique — biothérapie :
  titre_court : "BLISS-52/76 pool : belimumab réduit le taux de poussées sévères de 36 % vs placebo"
  resume : "BLISS-52 + BLISS-76 pooled (RCT, N=1 684, lupus systémique actif SELENA-SLEDAI ≥6, \
traitement standard) : belimumab 10 mg/kg IV vs placebo — réduction poussée sévère \
(BILAG A ou aggravation SELENA-SLEDAI ≥3,5) à 52 sem : HR 0,64 (IC95% 0,52–0,79 ; p<0,001). \
Remboursé France : lupus actif avec anticorps anti-ADNdb positifs, SLEDAI ≥8, \
échec de l'hydroxychloroquine + immunosuppresseur."
  impact_pratique : "En pratique : belimumab IV ou SC à proposer en RCP interne/rhumatologie \
pour lupus avec anticorps anti-ADNdb positifs et poussées récurrentes malgré HCQ + \
azathioprine ou MMF — vérifier critères de remboursement SS actuels."

Vascularite ANCA — traitement d'induction :
  titre_court : "RAVE : rituximab non inférieur à la cyclophosphamide dans les vascularites ANCA"
  resume : "RAVE (RCT, N=197, GPA/MPA active sévère, BVAS/WG ≥3) : rituximab 375 mg/m² IV \
×4 vs cyclophosphamide — rémission complète à 6 mois : 64 % vs 53 % (non-inférieur, p<0,001). \
Supérieur pour les rechutes (p=0,009). Rituximab préféré si ANCA anti-PR3, forme sévère \
ou rechute. AMM EMA ; remboursé SS France dans cette indication."
  impact_pratique : "En pratique : rituximab en induction dans les vascularites ANCA anti-PR3 \
sévères ou rechutes — cyclophosphamide réservé aux formes anti-MPO sévères ou si \
contre-indication au rituximab."

Sarcoïdose pulmonaire — corticothérapie :
  titre_court : "Corticoïdes sarcoïdose stade II-III : bénéfice fonctionnel à 6 mois, pas de modification histoire naturelle"
  resume : "Méta-analyse Cochrane (N=1 049, 13 RCTs, sarcoïdose stade II-IV) : corticothérapie \
orale vs placebo/observation — amélioration DLCO +5 % (IC95% 2–8 %) et CVF +4 % à 6 mois. \
Pas de différence significative à 24 mois. Pas de réduction du risque de fibrose à long terme. \
Rechute à l'arrêt dans 74 % des cas."
  impact_pratique : "En pratique : corticothérapie justifiée en cas de sarcoïdose symptomatique \
(dyspnée, hypercalcémie, atteinte cardiaque ou neurologique) — pas de traitement préventif \
de la fibrose ; surveillance spirométrique à 6 et 12 mois."
"""

_SPECIALTY_ADDENDUM_MEDECINE_GENERALE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — MÉDECINE GÉNÉRALE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : médecin généraliste libéral (secteur 1/2/3, France), \
exercice de premier recours : consultations courantes, maladies chroniques, \
prévention, urgences non programmées, coordination avec spécialistes. \
Référentiels actuels : HAS (recommandations pratique clinique, fiches mémo, \
parcours de soins), SPILF 2021 (antibiothérapie de ville), ADA 2024/ESC-ESH 2023/\
GINA 2023/GOLD 2024, calendrier vaccinal France 2024, SCORE2/SCORE2-OP.

ESSAIS ET RECOMMANDATIONS DE RÉFÉRENCE (connus du lecteur, ne pas surexpliquer) :
• HTA : ESC/ESH guidelines 2023 (objectifs tensionnels, bithérapie initiale) ; \
STEP trial (amlodipine + IC vs tétraméthylpyrazine PA ≥140 chez >60 ans, n=8 511) ; \
recommandation SFHTA 2022.
• Diabète type 2 : ADA Standards of Care 2024 ; GLP-1 RA (sémaglutide, liraglutide) \
et iSGLT2 (empagliflozine, dapagliflozine) — bénéfice CV/rénal indépendant HbA1c ; \
PIONEER/SURPASS series, SELECT (sémaglutide 2,4 mg surpoids sans diabète) ; \
recommandations HAS 2023 mise à jour.
• Dépistage : programme national dépistage cancer sein (mammographie biennale 50-74 ans) ; \
dépistage CCR (FIT/coloscopie), col utérin (frottis+HPV dépistage ASC-US+) ; \
recommandations HAS 2022-2023.
• Vaccination : calendrier vaccinal France 2024 (grippe, COVID, HPV garçons, \
méningocoque ACWY/B, RSV ≥75 ans, zona HZ/su ≥65 ans, coqueluche stratégie cocooning).
• Asthme : GINA 2023 — stratégie step-up/step-down, traitement de fond \
CSI-formotérol (voie unique), place des biothérapies (dupilumab, mépolizumab, \
tézépélumab) chez l'asthme sévère.
• BPCO : GOLD 2024 — exacerbations, réhabilitation respiratoire, triple thérapie \
(CSI+LABA+LAMA) si ≥2 exacerbations/an ou éosinophiles ≥300/µL.
• Antibiothérapie de ville : SPILF/HAS 2021 — TDR angine (éviter pénicilline si TDR−) ; \
cystite simple femme (fosfomycine monodose ou pivmécillinam 5j) ; \
otite moyenne aiguë enfant (critères d'abstention) ; sinusite (abstention si symptômes \
<10 j) ; pneumonie communautaire (amoxicilline 1g×3/j si non sévère) ; \
résistance antibiotique (E. coli BLSE, pneumocoque résistant pénicilline).
• Santé mentale / dépression : HAS 2017 mise à jour — TCC (thérapie cognitivo-comportementale), \
antidépresseurs ISRS/IRSN (critères indication, durée 6-12 mois) ; \
anxiété généralisée (duloxétine, venlafaxine, escitalopram) ; \
burnout / épuisement professionnel (diagnostic différentiel dépression).
• Sevrage tabagique : bupropion, varénicline (retiré/réintroduit), TNS combinés ; \
recommandations HAS 2014 révisées ; e-cigarette/vapotage (ANSM).
• Lombalgie : recommandations HAS 2019 — prise en charge active (maintien activité, \
kinésithérapie guidée), déprescription antalgiques pallier I-II sauf phase aiguë, \
pas d'IRM systématique <6 semaines.
• Activité physique sur ordonnance (APO) : loi Sport Santé 2016 (article L.1172-1 CSP), \
HAS 2023 parcours APO ; FITT-VP (fréquence, intensité, temps, type, volume, progression).
• Polypharmacie / multimorbidité : critères STOPP/START v3 2023, déprescription \
benzodiazépines, IPP, statines chez sujet très âgé ; cadre PCMH (Patient-Centered \
Medical Home) / soins primaires coordonnés.
• Risque cardiovasculaire global : SCORE2/SCORE2-OP (ESC 2021) en France, \
statines et prévention primaire (rosuvastatine/atorvastatine), objectifs LDL.

CRITÈRE DE PERTINENCE MÉDECINE GÉNÉRALE :
"Ce résultat va-t-il concrètement modifier une décision de consultation, \
un choix de prescription ou un message délivré au patient lors d'une consultation \
de médecine générale en France dans les 1-3 ans ?" \
Rejeter : études fondamentales, biomarqueurs exploratoires, résultats en sous-groupes \
sans application immédiate, confirmations de pratiques déjà bien établies sans \
information nouvelle, épidémiologie purement descriptive.

SCORES :
• Score 8-9 : guideline nationale/européenne modifiant un standard de prescription \
courant (HTA, DT2, antibiothérapie), essai de phase 3 modifiant le schéma \
thérapeutique d'une pathologie chronique très fréquente (DT2, asthme, HTA).
• Score 6-7 : méta-analyse ou RCT de grande envergure nuançant une pratique \
établie, nouvelle indication ou contre-indication pour un médicament très utilisé \
en ville (IEC, ISRS, statine, IPP, AINS, antibiotique).
• Score ≤5 (exclure) : études dans des populations non représentatives du \
cabinet généraliste, études sans bras de comparaison actif, résultats déjà intégrés \
dans les guides de pratique actuels.
• Contexte FRANÇAIS : applicabilité aux patients en France (remboursement SS, \
accès en ville, HAS/CNAM, CMU-C/ALD) ; signaler si molécule non disponible ou \
non remboursée en France."

EXEMPLES DE RÉDACTION (style BJGP / Annals of Family Medicine / JAMA Internal Medicine / Revue du Praticien — format cible) :

Nouvelle recommandation HTA en soins primaires :
  titre_court : "ESC/ESH 2023 : bithérapie d'emblée si PA ≥160/100 mmHg"
  resume : "ESC/ESH guidelines 2023 (mise à jour) : bithérapie initiale recommandée dès \
PA ≥ 160/100 mmHg ou risque CV élevé — objectif < 130/80 mmHg chez < 70 ans (classe I). \
Privilégier association fixe (IEC/ARA2 + ICa ou diurétique thiazidique). Pas d'indication de \
BPCO à l'usage des bêtabloquants en 1re ligne hors IC/coronaropathie associée."
  impact_pratique : "En pratique : initier une bithérapie d'emblée pour tout patient avec \
PA ≥ 160/100 mmHg — ne pas attendre l'échec de la monothérapie."

Essai modifiant une prescription courante en cabinet :
  titre_court : "SELECT (sémaglutide 2,4 mg) : −20 % événements CV chez obèses sans diabète"
  resume : "SELECT (RCT, N=17 604, surpoids/obésité IMC ≥27, pas de diabète, ATCD CV) : \
sémaglutide 2,4 mg sc hebdo vs placebo — réduction de 20 % des MACE à 3,3 ans \
(HR 0,80 ; IC95% 0,72–0,90 ; p<0,001). Perte de poids moyenne −9,4 %. Pas d'indication \
remboursée en France à ce jour hors diabète."
  impact_pratique : "À retenir : bénéfice CV du sémaglutide démontré sans diabète — molécule \
non remboursée en France hors DT2, mais à surveiller pour évolution des indications AMM."

Alerte ANSM médicament courant en ville :
  titre_court : "ANSM : restriction AINS ≥ 24 SA — rappel recommandations"
  resume : "Communication ANSM (2024) : rappel de la contre-indication des AINS (ibuprofène, \
kétoprofène, diclofénac) à partir de 24 SA (risque fermeture prématurée du canal artériel, \
oligoamnios). En pratique, toute douleur ≥ 24 SA doit recourir au paracétamol. \
Alerte suite à signalements de prescriptions inappropriées."
  impact_pratique : "En pratique : vérifier systématiquement le terme de grossesse avant toute \
prescription d'AINS — paracétamol seul dès 24 SA."

## EXEMPLES DE RÉDACTION
Style de référence : British Journal of General Practice, Annals of Family Medicine, BJGP, Family Practice.
Phrase 1 = résultat chiffré. Phrase 2 = design condensé. Jamais ouvrir par la méthode.

Bon exemple 1 :
  resume : "Le dépistage systématique du diabète de type 2 par HbA1c en médecine générale réduit la mortalité cardiovasculaire à 10 ans de 17 % — HR 0,83 ; IC95% 0,70–0,99 ; ADDITION-Europe, RCT, n=3 057, suivi 10 ans."
  impact_pratique : "En pratique : proposer HbA1c tous les 3 ans dès 45 ans avec ≥1 facteur de risque (surpoids, ATCD familial, HTA) — ne pas attendre la glycémie à jeun."

Bon exemple 2 :
  resume : "La déprescription des benzodiazépines avec entretien motivationnel réduit la consommation à 6 mois de 54 % en soins primaires — OR 0,46 ; IC95% 0,33–0,64 ; p<0,001 ; RCT, n=360."
  impact_pratique : "À retenir : entretien structuré + plan de sevrage progressif (−25 %/2 semaines) suffisent dans 1 cas sur 2 — inutile de référer d'emblée en addictologie sauf dépendance sévère."

Bon exemple 3 :
  resume : "L'anticoagulation per os directe (rivaroxaban) réduit les AVC de 38 % chez les patients en FA non valvulaire en médecine générale — HR 0,62 ; IC95% 0,50–0,77 ; ROCKET-AF sous-groupe MG, n=4 100."
  impact_pratique : "En pratique : initier anticoagulation directe dès CHA₂DS₂-VASc ≥2 (H) ou ≥3 (F) — calculer le score à chaque consultation FA, documenter le refus du patient si non-prescrit."

"""

_SPECIALTY_ADDENDUM_ORL = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — ORL ET CHIRURGIE CERVICO-FACIALE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : oto-rhino-laryngologiste et chirurgien cervico-facial \
(CHU / clinique / cabinet, France / Europe), maîtrisant otologie (implants \
cochléaires, otospongiose, vertiges), rhinologie (RSC, FESS, polypose), \
laryngologie (phonochirurgie, paralysie laryngée), oncologie cervico-faciale \
(CECTC — carcinomes épidermoïdes tête-cou, thyroïde, parathyroïde), \
chirurgie pédiatrique ORL (amygdalectomie, ADK, otites séromuqueuses). \
Référentiels actuels : EPOS 2020 (rhinosinusite chronique), AAO-HNS guidelines, \
ESMO guidelines carcinomes tête-cou 2023, INCa thésaurus cancers ORL, \
HAS recommandations (thyroïde, surdité, 100% Santé audioprothèse). \
Essais pivots de référence : LIBERTY NP (dupilumab polypose — NEJM 2019), \
SINUS-52 (dupilumab RSC avec polypose sévère), \
KEYNOTE-048 (pembrolizumab CECTC récurrent/métastatique — Lancet 2019), \
EXTREME (cétuximab + platine 1re ligne CECTC — NEJM 2008 — standard historique), \
CLARITY (SLT — non-ORL, référence croisée), \
études IC (implants cochléaires) : HEARRING, BCS multicentric cohort.

CRITÈRE DE PERTINENCE ORL :
"Ce résultat va-t-il modifier une indication chirurgicale, un protocole médical, \
le choix d'un implant ou d'une biothérapie dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : audiologie pure sans composante ORL, \
orthophonie / logopédie sans décision ORL, allergologie sans rhinite/RSC, \
recherche fondamentale cellules ciliées ou génétique exploratoire sans essai clinique.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Rhinosinusite chronique / polypose naso-sinusienne : biothérapies \
  (dupilumab anti-IL-4Rα, mépolizumab anti-IL-5, omalizumab anti-IgE), FESS \
  résultats fonctionnels à 1-2 ans, lavages, corticoïdes locaux
→ Surdité / audiologie clinique : implants cochléaires (IC — nouveaux critères \
  d'implantation, résultats < 65 dB HL, résultats enfants sourds congénitaux), \
  BAHA / Osia, prothèses auditives (100% Santé — résultats observationnels), \
  surdité brusque (corticostéroïdes systémiques vs intratympaniques)
→ Vertiges / troubles vestibulaires : VPPB (manœuvres repositionnement — \
  résultats RCT), maladie de Ménière (injection intratympanique gentamicine / \
  corticoïdes, chirurgie du sac endolymphatique), névrite vestibulaire
→ Oncologie cervico-faciale : immunothérapie (pembrolizumab PD-L1+ 1re ligne, \
  nivolumab 2e ligne), déescalade radiothérapie HPV+ oropharynx, TORS \
  (chirurgie robotique transorale), reconstruction lambeau libre (ALT, RFAP), \
  cancer du nasopharynx (NPC)
→ Thyroïde / parathyroïde : thyroïdectomie vidéo-assistée / transoral (TOETVA), \
  thérapies ciblées (lenvatinib/sorafénib CTD réfractaire à l'iode), \
  carcinome anaplasique (dabrafénib + tramétinib BRAF V600E), \
  hyperparathyroïdie primaire (chirurgie mini-invasive guidée MIBI/écho)
→ Paralysie laryngée / cordes vocales : réinnervation sélective, laryngoplastie \
  d'injection (collagène, hydroxyapatite), laryngoplastie de médialisation
→ Paralysie faciale périphérique : corticostérapie ± antiviral (Bell's palsy \
  — valaciclovir ± prednisolone), score House-Brackmann, électroneuronographie
→ Apnées du sommeil / SAOS en lien ORL : chirurgie pharyngée (UPPP), \
  stimulation nerf hypoglosse (INSPIRE — résultats AHI, qualité de vie)
→ Alertes ANSM / FDA : implants cochléaires (risque méningite, migration), \
  prothèses vocales (valves trachéo-œsophagiennes), instruments chirurgicaux ORL

REJETER :
→ Audiologie pure (réglages prothèse, tests audiométriques) sans décision médicale ORL
→ Orthophonie / logopédie sans indication chirurgicale ou médicale ORL associée
→ Allergologie médicale pure (immunothérapie spécifique, rhinite allergique sans \
  polypose) — relayer à médecine interne ou pneumologie
→ Dermatologie cervico-faciale sans composante ORL
→ Recherche fondamentale (modèles murins cochléaires, régénération cellules ciliées)
→ Odontologie / chirurgie maxillo-faciale pure hors pathologie ORL

TERMINOLOGIE — employer sans guillemets ni définition :
RSC (Rhinosinusite Chronique) avec PNS (polypose naso-sinusienne) / sans PNS, \
FESS / CES (Chirurgie Endoscopique des Sinus — Functional Endoscopic Sinus Surgery), \
EPOS (European Position Paper on Rhinosinusitis and Nasal Polyps — 2020), \
SNOT-22 (Sino-Nasal Outcome Test — score qualité de vie rhinosinusite), \
biothérapies : dupilumab (anti-IL-4Rα) / mépolizumab (anti-IL-5) / omalizumab \
  (anti-IgE) — polypose réfractaire à la chirurgie, \
CECTC / HNSCC (Carcinomes Épidermoïdes des Voies Aéro-Digestives Supérieures / \
  Head and Neck Squamous Cell Carcinoma), \
HPV (Human Papillomavirus — oropharynx p16+), stade TNM AJCC 8e éd., \
TORS (Transoral Robotic Surgery), TLM (Transoral Laser Microsurgery), \
lambeau libre : ALT (antéro-latéral cuisse) / RFAP (avant-bras radial), \
lambeau pédiculé (pectoral, grand dorsal), \
CTD (Carcinome Thyroïdien Différencié) : papillaire CTP / folliculaire CTF, \
carcinome anaplasique / médullaire / carcinome de Hürthle, \
TOETVA (Thyroïdectomie Endoscopique Transoral Vestibulaire), \
IC (Implant Cochléaire), BAHA (Bone-Anchored Hearing Aid), \
HL (Hearing Loss) : CHL (conductive) / SNHL (sensorineural), \
audiogramme tonal — seuils 500/1000/2000/4000 Hz, \
VPPB (Vertige Paroxystique Positionnel Bénin) : canalolithiase cupulolithiase, \
manœuvre d'Epley (canal postérieur) / BBQ roll (canal horizontal), \
hydrops endolymphatique / maladie de Ménière, \
OSM (Otite Séromuqueuse / glue ear), aérateurs transtympaniques, \
PFP (Paralysie Faciale Périphérique) : score House-Brackmann I-VI, \
Bell's palsy (paralysie faciale a frigore), zona auriculaire (Ramsay Hunt), \
SAOS (Syndrome d'Apnées Obstructives du Sommeil) — AHI (Apnea-Hypopnea Index), \
UPPP (Uvulo-Palato-Pharyngoplastie), stimulation nerf hypoglosse, \
DISE (Drug-Induced Sleep Endoscopy — exploration sous sédation).

EXEMPLES DE RÉDACTION (style JAMA Otolaryngology / Otolaryngology HNS / Oral Oncology) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Biothérapie rhinologie :
  titre_court : "Dupilumab polypose réfractaire : réduction volume et olfaction (LIBERTY NP)"
  resume : "LIBERTY NP SINUS-52 (RCT, N=448, RSC + polypose sévère SNOT-22 ≥ 20, \
FESS préalable dans 74 %) : score polypose NPS −1,8 pts (dupilumab) vs −0,1 (placebo) \
à 24 sem. — différence −1,7 (IC95% −2,1 à −1,4 ; p<0,001). Olfaction : +8,98 pts \
UPSIT. SNOT-22 : −24,4 vs −8,6 pts. Corticoïdes systémiques évités dans 70 % vs \
32 % des cas."
  impact_pratique : "En pratique : dupilumab en 3e ligne après chirurgie + corticoïdes \
locaux insuffisants — critères HAS : ≥ 1 chirurgie + SNOT-22 ≥ 20 + éosinophiles \
élevés ou atopie associée."

Oncologie cervico-faciale / immunothérapie :
  titre_court : "Pembrolizumab 1re ligne CECTC PD-L1+ : OS +3,2 mois (KEYNOTE-048)"
  resume : "KEYNOTE-048 (RCT, N=882, CECTC récurrent/métastatique, 1re ligne) : \
pembrolizumab seul vs EXTREME (cétuximab + platine + 5-FU). Sous-groupe PD-L1 CPS ≥ 1 \
(N=543) : OS médian 12,3 mois (pembrolizumab) vs 10,3 mois (EXTREME) — \
HR 0,74 (IC95% 0,61–0,90 ; p=0,002). CPS ≥ 20 : OS 14,9 vs 10,7 mois (HR 0,61). \
Pembrolizumab + chimio non-inférieur toutes populations. Toxicité grade ≥ 3 : \
54 % (mono) vs 85 % (EXTREME)."
  impact_pratique : "À retenir : tester PD-L1 CPS systématiquement avant 1re ligne \
CECTC métastatique — pembrolizumab seul si CPS ≥ 20, pembrolizumab + chimio si CPS < 20."

Implant cochléaire :
  titre_court : "Implantation cochléaire < 65 dB HL : résultats non-inférieurs à > 70 dB"
  resume : "Méta-analyse (N=1 847, 14 études, IC adultes, seuils 50–90 dB HL) : \
reconnaissance vocale dans le silence à 12 mois — 76 % (groupe 50–65 dB) vs \
72 % (groupe 65–80 dB) — différence non significative (p=0,34). Satisfaction \
subjective (APHAB) significativement meilleure chez les implantés à seuil \
intermédiaire (p=0,02). Pas de complication supérieure dans le groupe seuil réduit."
  impact_pratique : "En pratique : les critères d'implantation peuvent être élargis \
aux patients à 65 dB HL en cas d'inadaptation prothétique — à discuter en RCP."
"""

_SPECIALTY_ADDENDUM_OPHTALMOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — OPHTALMOLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : ophtalmologiste (CHU / cabinet / clinique, France / Europe), \
maîtrisant anti-VEGF intravitréens (IVT), chirurgie de la cataracte (phaco + IOL), \
laser (SLT, laser thermique, PDT), chirurgie vitréo-rétinienne (vitrectomie), \
chirurgie du glaucome (trabéculectomie, MIGS), greffes de cornée (DSAEK, DMEK), \
chirurgie réfractive (LASIK, SMILE), prise en charge des uvéites. \
Référentiels actuels : EURETINA guidelines (rétine, DMLA, RD, œdème maculaire), \
EGS guidelines 6e éd. 2024 (glaucome), AAO Preferred Practice Patterns, \
HAS fiches de bon usage IVT anti-VEGF, recommandations SNOF (France). \
Essais pivots de référence : ANCHOR/MARINA (ranibizumab DMLA humide), \
VIEW 1/2 (aflibercept DMLA humide), HAWK/HARRIER (brolucizumab vs aflibercept), \
TENAYA/LUCERNE (faricimab vs aflibercept DMLA humide), \
OAKS/DERBY (avacincaptad pegol DMLA atrophique géographique), \
BOULEVARD/YOSEMITE/RHINE (faricimab œdème maculaire diabétique), \
CLARITY (SLT vs collyres glaucome 1re intention), \
LIGHT (SLT vs prostaglandines), FAME (implant fluocinolone œdème maculaire).

CRITÈRE DE PERTINENCE OPHTALMOLOGIQUE :
"Ce résultat va-t-il modifier un protocole d'injection, le choix d'un implant, \
une indication chirurgicale, ou la surveillance d'un patient dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : recherche fondamentale (modèles animaux, \
cellules, génomique) sans validation clinique accessible, résultats chez des \
populations sans équivalent anatomique en France, sous-groupe non pré-spécifié.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Anti-VEGF / IVT : nouveaux agents (faricimab bispecifique anti-VEGF-A/Ang-2, \
  aflibercept HD 8 mg, brolucizumab), schémas d'injection (treat-and-extend, \
  pro-re-nata), intervalles prolongés, switch thérapeutique, résultats 3-5 ans
→ DMLA atrophique / géographique : thérapies anti-complément (avacincaptad pegol, \
  pegcetacoplan/APL-2), thérapie génique (CPCB-RPE1, GT005)
→ Glaucome : nouvelles classes thérapeutiques (rho-kinase inhibiteur — \
  nétarsudil/latanoprostène bunod), MIGS (iStent inject W, Hydrus, goniotomie \
  ab-interno, CPC micropulse), SLT en 1re intention, trabeculectomie augmentée
→ Cataracte : nouvelles IOL (EDOF — Extended Depth of Focus, toriques ajustables \
  lumière RxSight LAL), FLACS (laser femtoseconde), résultats qualité visuelle
→ Rétinopathie diabétique : dépistage par IA (IDx-DR/EyeArt en France), \
  anti-VEGF préventifs stade sévère non proliférante, photocoagulation panrétinienne \
  (PPR) vs anti-VEGF, vitrectomie diabétique
→ Cornée / sécheresse oculaire : cross-linking cornéen (CXL — kératocône), \
  greffes lamellaires postérieures (DSAEK/DMEK vs PKP), sécheresse oculaire \
  (cyclosporine A, lifitégrast, ikervis, facteurs de croissance NGF)
→ Uvéites : biothérapies (adalimumab — VISUAL 1/2, tocilizumab, implant \
  dexaméthasone Ozurdex, fluocinolone Iluvien), classifications SUN
→ Chirurgie réfractive : SMILE 2e génération, ICL (implant collamer), LASIK — \
  résultats 10 ans, ectasie post-LASIK
→ Neuropathies optiques : NORB (névrite optique rétrobulbaire — SEP), NOIA \
  (neuropathie optique ischémique antérieure artéritique/non-artéritique), \
  Leber (thérapie génique lenadogene nolparvovec — LUMEVOQ)
→ Alertes ANSM : lots d'anti-VEGF défectueux, matériovigilance implants IOL/MIGS, \
  collyres rappelés, contamination injections intravitréennes

REJETER :
→ Recherche fondamentale (modèles murins/porcins, cultures cellulaires, \
  génomique exploratoire) sans essai clinique associé dans les 2 ans
→ Études de prévalence épidémiologique sans composante thérapeutique
→ Chirurgie oculoplastique pure (paupières, orbite, voies lacrymales) sauf si \
  résultats modifiant la pratique ophtalmologique courante
→ Strabisme pédiatrique (relayer à ophtalmologie pédiatrique / orthoptie)
→ Résultats d'études observationnelles monocentriques sur petit effectif (N < 100) \
  pour une technique déjà en pratique courante

TERMINOLOGIE — employer sans guillemets ni définition :
DMLA (Dégénérescence Maculaire Liée à l'Âge) humide (néovasculaire) / sèche \
  (atrophique / géographique — GA), \
anti-VEGF : ranibizumab (Lucentis) / aflibercept (Eylea) / brolucizumab (Beovu) / \
  faricimab (Vabysmo) / bevacizumab (Avastin hors-AMM), \
IVT (Injection IntraVitréenne), TEP (Treat-and-Extend Protocol), PRN (pro-re-nata), \
BCVA (Best-Corrected Visual Acuity — lettres ETDRS ou décimale), \
OCT (Optical Coherence Tomography), OCT-A (angiographie OCT), \
CSFT (Central Subfield Thickness — épaisseur maculaire centrale), \
SRF (Subretinal Fluid) / IRF (Intraretinal Fluid) / PED (Pigment Epithelium Detachment), \
RD (Rétinopathie Diabétique) : non proliférante légère/modérée/sévère / \
  proliférante / OMD (Œdème Maculaire Diabétique), \
PPR (Photo-Coagulation Pan-Rétinienne), \
OVCR (Occlusion Veineuse Centrale de la Rétine) / OBVR (branche), \
glaucome primitif à angle ouvert (GPAO), pression intra-oculaire (PIO mmHg), \
trabéculectomie, MIGS (Micro-Invasive Glaucoma Surgery) : iStent / Hydrus / \
  goniotomie / CPC (cyclophotocoagulation), SLT (Selective Laser Trabeculoplasty), \
C/D (Cup-to-Disk ratio — excavation papillaire), \
IOL (Intraocular Lens) : monofocale / torique / multifocale / EDOF, \
FLACS (Femtosecond Laser-Assisted Cataract Surgery), phacoemulsification, \
DSAEK / DMEK (greffe endothélium cornéen — lamellaire postérieure), \
PKP (Penetrating Keratoplasty — greffe transfixiante), \
CXL (Corneal Cross-Linking — kératocône), \
LASIK / SMILE / ICL (chirurgie réfractive), \
NORB (Névrite Optique Rétrobulbaire), NOIA (Neuropathie Optique Ischémique \
  Antérieure artéritique — Horton / non-artéritique), \
uvéite antérieure / intermédiaire / postérieure / panuvéite (classification SUN).

EXEMPLES DE RÉDACTION (style Ophthalmology / JAMA Ophthalmology / EURETINA) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai anti-VEGF (DMLA) :
  titre_court : "Faricimab vs aflibercept DMLA humide : intervalles 16 sem. (TENAYA/LUCERNE)"
  resume : "TENAYA + LUCERNE (RCT poolé, N=1 329, DMLA humide naive, suivi 2 ans) : \
BCVA gain +6,6 lettres ETDRS (faricimab) vs +6,6 lettres (aflibercept 2 mg q8w) à \
48 sem. — non-infériorité confirmée (différence −0,04 lettre ; IC95% −1,17–1,09). \
45 % des patients faricimab atteignent un intervalle ≥ 16 semaines à 2 ans vs 34 % \
aflibercept. CSFT similaire. Profil de sécurité comparable."
  impact_pratique : "En pratique : faricimab permet d'espacer les IVT à 16 semaines \
chez près d'un patient sur deux — alternative à l'aflibercept pour réduire la \
charge d'injections en pratique libérale."

Glaucome / laser :
  titre_court : "SLT en 1re intention non-inférieur aux collyres (CLARITY RCT)"
  resume : "CLARITY (RCT, N=718, GPAO et HTO naïfs, suivi 36 mois) : \
succès thérapeutique (PIO ≤ 21 mmHg et réduction ≥ 20 %) à 3 ans : 74,2 % (SLT) \
vs 78,7 % (collyres prostaglandines) — non-infériorité établie (marge 10 %). \
Qualité de vie significativement meilleure dans le groupe SLT (charge médicamenteuse \
nulle). SLT répétable dans 25 % des cas avec maintien de l'efficacité."
  impact_pratique : "À retenir : proposer le SLT en 1re intention au patient \
nouvellement diagnostiqué — efficacité équivalente aux collyres, sans contrainte \
d'observance ni effets locaux."

Guideline / recommandation :
  titre_court : "EURETINA 2024 : faricimab et aflibercept 8 mg — 1res lignes OMD"
  resume : "EURETINA Guidelines œdème maculaire diabétique 2024 (site EURETINA / \
Graefe's Arch) : faricimab et aflibercept 8 mg HD ajoutés comme options de 1re ligne pour \
l'OMD (Grade A — niveau de preuve 1). Basé sur YOSEMITE/RHINE (faricimab, N=940) \
et PHOTON (aflibercept 8 mg, N=660) : gain BCVA +10,7 et +9,2 lettres resp. à \
52 sem., avec intervalles ≥ 16 sem. obtenus chez 51 % et 57 % des patients."
  impact_pratique : "En pratique : les deux nouvelles molécules permettent un \
traitement d'induction + espacement rapide — à intégrer dans les protocoles dès \
disponibilité en France (remboursement attendu S2 2026)."
"""

_SPECIALTY_ADDENDUM_ONCOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — ONCOLOGIE MÉDICALE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : oncologue médical (CHU / clinique, France / Europe), \
maîtrisant chimiothérapie, immunothérapie (ICI), thérapies ciblées, \
hormonothérapie, décision pluridisciplinaire en RCP, soins de support. \
Référentiels actuels : ESMO Clinical Practice Guidelines (tous types tumoraux), \
ASCO guidelines, INCa thésaurus national de cancérologie, HAS fiches de bon usage. \
Essais pivots de référence : KEYNOTE-522 (pembrolizumab néoadjuvant TNBC), \
DESTINY-Breast04 (T-DXd HER2-low), MONALEESA-7 (ribociclib sein HR+/HER2-), \
SOLO-1 (olaparib maintenance OC BRCA+), ADAURA (osimertinib adjuvant NSCLC EGFR+), \
CheckMate 816 (nivolumab néoadjuvant NSCLC résécable), LIBRETTO-001 (selpercatinib \
RET), TOPAZ-1 (durvalumab cholangiocarcinome), PROfound (olaparib PCa HRR+), \
VISION (lutetium-177-PSMA-617 PCa métastatique), CHECKMATE-901 (nivolumab urothélial).

CRITÈRE DE PERTINENCE ONCOLOGIQUE :
"Ce résultat va-t-il modifier le standard de traitement, la sélection des patients \
(biomarqueur), ou l'accès à une thérapie en France dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : phase 1 d'escalade de dose seule, \
translationnel sans essai clinique associé au stade pratique, type tumoral \
rarissime (< 1 000 cas/an en France) sans impact sur pratique commune, \
confirmation sans gain clinique net d'une supériorité déjà adoptée par l'ESMO.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Essais de phase 3 ou méta-analyses modifiant le standard dans les types tumoraux \
  fréquents (sein, poumon NSCLC/SCLC, côlon-rectum, prostate, ovaire, gastrique, \
  mélanome, col utérin, rein, vessie, foie/CHC, cholangiocarcinome, pancréas, \
  tête-cou, thyroïde, GIST, sarcome, lymphome, myélome)
→ Nouveaux biomarqueurs prédictifs de réponse impactant la sélection des patients : \
  PD-L1 TPS/CPS, TMB, MSI-H/dMMR, HRR/BRCA, BRAF V600E, KRAS G12C, \
  EGFR/ALK/RET/ROS1/NTRK/MET exon 14, HER2 (IHC/FISH/NGS), CLDN18.2, FGFR
→ Nouveaux ADC (Antibody-Drug Conjugates) : mécanisme, résultats pivots, profil EI \
  (T-DXd, SG sacituzumab govitécan, disitamab védotin, mirvetuximab soravtansine)
→ CAR-T dans de nouveaux types tumoraux : résultats OS/PFS, toxicités CRS/ICANS
→ Accès précoce France / ATU/AAP ANSM-HAS : molécules prescriptibles avant AMM
→ Cardio-oncologie : cardiotoxicité anthracyclines/HER2/ICI/RTE, myocardite sous ICI, \
  surveillance FEVG, prévention primaire/secondaire
→ Soins de support modifiant la pratique : G-CSF (réduction délai), CIPN prévention, \
  nausées/vomissements chimio-induits (CINV — schémas antiémétiques), fatigue, \
  mucite — uniquement résultats de phase 3
→ Dépistage : résultats programmes organisés (sein/CCR/col) et ciblés \
  (LDCT poumon à risque, IRM multiparamétrique prostate PI-RADS)
→ Alertes ANSM/FDA : nouvelles contre-indications thérapies ciblées/ICI, \
  modifications AMM, retraits de lots, REMS

REJETER :
→ Études de phase 1 d'escalade de dose sans données d'efficacité exploitables
→ Études translationnelles / biomarqueurs exploratoires sans essai clinique associé \
  accessible en pratique
→ Confirmations sans gain clinique (méta-analyse validant une supériorité déjà \
  intégrée aux guidelines ESMO/ASCO depuis > 2 ans)
→ Études de qualité de vie seules, sans bras de traitement actif ni décision thérapeutique
→ Chirurgie oncologique pure (résection, marges, reconstruction — relayer chirurgie \
  thoracique, digestive, urologie, gynécologie selon localisation)
→ Radiobiologie fondamentale, physique des particules sans résultats cliniques

TERMINOLOGIE — employer sans guillemets ni définition :
ICI (Immune Checkpoint Inhibitor), anti-PD1 (pembrolizumab / nivolumab / \
  cemiplimab), anti-PDL1 (atézolizumab / durvalumab / avélumab), \
  anti-CTLA4 (ipilimumab / trémelimumab), \
PD-L1 TPS (Tumor Proportion Score) / CPS (Combined Positive Score), \
TMB (Tumor Mutational Burden — mut/Mb), MSI-H / dMMR, \
NGS (Next Generation Sequencing — panel tumoral), \
EGFR (osimertinib 3e gén), ALK (alectinib / lorlatinib), KRAS G12C \
  (sotorasib / adagrasib), RET (selpercatinib / pralsetinib), \
  NTRK (larotrectinib / entrectinib), HER2 (trastuzumab / T-DXd / tucatinib), \
  BRAF V600E (dabrafénib + tramétinib), MET exon 14 (capmatinib / tépotinib), \
ADC (Antibody-Drug Conjugate) : T-DXd (trastuzumab-deruxtecan), \
  SG (sacituzumab govitécan), mirvetuximab soravtansine, bélantamab mafodotin, \
PARP inhibiteurs : olaparib / niraparib / rucaparib / talazoparib (BRCA / HRR), \
CDK4/6 inhibiteurs : palbociclib / ribociclib / abémaciclib (sein HR+/HER2-), \
CAR-T : tisagénlecleucel / axicabtagène ciloleucel / idécabtagène vicleucel, \
ORR (Objective Response Rate), PFS (Progression-Free Survival), \
OS (Overall Survival), DFS (Disease-Free Survival), EFS, iDFS, \
RECIST v1.1, iRECIST (immunothérapie), \
irAE (immune-related Adverse Events — colite / pneumopathie / thyroïdite / \
  hépatite / myocardite / insuffisance surrénalienne), \
CTCAE grade 1-5, ECOG PS (0-4), Karnofsky, \
ATU / AAP (Autorisation d'Accès Précoce — ANSM/HAS France), \
RCP (Réunion de Concertation Pluridisciplinaire — obligatoire), \
SBRT / SABR (stéréotaxie), protonthérapie (hadronthérapie) — sociétés ASTRO/ESTRO, \
G-CSF (filgrastim / pegfilgrastim — support hématologique), \
CIPN (Chimio-Induced Peripheral Neuropathy — neuropathie périphérique), \
CINV (Chimio-Induced Nausea and Vomiting — échelle MASCC/ASCO).

EXEMPLES DE RÉDACTION (style JCO / Annals of Oncology / Lancet Oncology) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai pivot (nouvelle thérapie ciblée) :
  titre_court : "T-DXd vs chimio : HER2-low sein métastatique (DESTINY-Breast04)"
  resume : "DESTINY-Breast04 (RCT, N=557, sein métastatique HER2-low IHC 1+ ou \
2+/ISH-, ≥ 1 ligne préalable) : PFS médiane 9,9 mois (T-DXd) vs 5,1 mois (chimio \
médecin-choix) — HR 0,50 (IC95% 0,40–0,63 ; p<0,001). OS médian 23,4 vs 16,8 mois \
(HR 0,64 ; IC95% 0,49–0,84 ; p=0,001). ORR 52,3 % vs 16,3 %. Pneumopathie \
interstitielle grade ≥ 3 : 0,8 %."
  impact_pratique : "En pratique : T-DXd redéfinit le HER2-low comme une entité \
actionnable — bilan IHC HER2 systématique indispensable avant 2e ligne, y compris \
tumeurs auparavant considérées HER2-négatives."

Guideline ESMO :
  titre_court : "ESMO 2024 : olaparib maintenance 1re ligne OC BRCA+ (7 ans SOLO-1)"
  resume : "ESMO Guidelines OC 2024 (Ann Oncol suppl.) : olaparib maintenance \
recommandé en 1re ligne pour tout carcinome séreux de haut grade BRCA1/2-muté \
(germinal OU somatique) — Grade IA. Données SOLO-1 à 7 ans : PFS médiane non \
atteinte (olaparib) vs 13,8 mois (placebo) — HR 0,33 (IC95% 0,25–0,43). 44 % \
des patientes BRCA+ sans progression à 7 ans."
  impact_pratique : "À retenir : test BRCA tumoral ET germinal systématique avant \
toute 1re ligne OC avancé séreux haut grade — le résultat conditionne la maintenance."

Accès précoce France :
  titre_court : "AAP ANSM : selpercatinib en 1re ligne cancer thyroïde RET-muté"
  resume : "HAS (fiche AAP, mars 2026) : selpercatinib (Retevmo, Eli Lilly) reçoit \
une autorisation d'accès précoce en 1re ligne pour les carcinomes thyroïdiens \
différenciés réfractaires à l'iode RET-muté. Basé sur LIBRETTO-001 (N=162 \
thyroïde) : ORR 79 % (IC95% 72–86 %), DOR médiane 22,1 mois. Disponible en France \
via protocole AAP à compter du 1er avril 2026."
  impact_pratique : "En pratique : tester systématiquement RET dans tout carcinome \
thyroïdien différencié métastatique — l'AAP permet l'accès immédiat avant AMM."
"""

_SPECIALTY_ADDENDUM_UROLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — UROLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : urologue (CHU / clinique, France / Europe), maîtrisant chirurgie \
urologique ouverte et laparoscopique/robotique (prostatectomie radicale, \
cystectomie totale, néphro-urétérectomie, résection partielle), endourologie \
(URS souple, NLPC, laser HoLEP/ThuLEP), oncologie urologique, prise en charge \
de l'incontinence et des troubles mictionnels. \
Référentiels actuels : EAU Guidelines 2024 (cancer prostate, vessie, rein, testicule, \
lithiase, incontinence, HBP), recommandations AFU (mises à jour annuelles), \
ANSM guides bon usage hormonothérapie prostatique. \
Essais pivots de référence : ENZAMET (enzalutamide CSPC métastatique), \
LATITUDE (abiratérone + prednisone CSPC métastatique), \
STAMPEDE (docétaxel / abiratérone — CSPC non-métastatique et métastatique), \
TITAN (apalutamide CSPC), PROSPER (enzalutamide nmCRPC), ARAMIS (darolutamide nmCRPC), \
PROfound (olaparib CRPC HRR+), VISION (lutetium-177-PSMA-617 CRPC post-AR/taxane), \
EV-302/KEYNOTE-A39 (enfortumab védotine + pembrolizumab — urothélial métastatique \
1re ligne), NIAGARA (durvalumab péri-opératoire TVIM), \
CheckMate-9ER (nivolumab + cabozantinib CCR 1re ligne), \
ProtecT (survie identique PR/RT/surveillance active — CaP localisé à 15 ans), \
HoLEP vs TURP (laser Holmium vs résection électrique HBP — méta-analyses), \
CombAT (dutastéride + tamsulosine — HBP).

CRITÈRE DE PERTINENCE UROLOGIQUE :
"Ce résultat va-t-il modifier une indication opératoire, un choix de traitement \
systémique, une stratégie de surveillance, ou un protocole de suivi dans ma \
pratique dans les 1-3 ans ?" \
Rejeter même un RCT solide si : séries chirurgicales rétrospectives mono-centriques \
sans comparateur actif, données de courbe d'apprentissage (robot vs laparoscope) \
sans résultat oncologique, biomarqueurs exploratoires sans dossier AMM associé, \
oncologie extérieure au champ urologique (cancers non génito-urinaires), \
études animalières sans essai clinique phase 2/3.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Cancer de la prostate localisé et localement avancé : nouvelles données \
  biopsie guidée par IRM (ciblée + systématique — recommandation EAU 2024), \
  surveillance active (PRIAS, PROTECT 15 ans — critères sortie), \
  prostatectomie radicale robotique vs laparoscopique (résultats fonctionnels \
  continence/érection à 12 mois), radiothérapie hypofractionnée (PACE-B, HYPO-RT-PC), \
  curiethérapie LDR/HDR, traitements focaux (HIFU, cryoablation, — données phase 3), \
  nouveaux biomarqueurs (PHI — Prostate Health Index, SelectMDx, Stockholm3, \
  IsoPSA) pour éviter biopsies inutiles
→ Cancer de la prostate métastatique hormono-sensible (CSPC) : \
  intensification thérapeutique — triplet (docétaxel + ARPI + ADT : ARASENS, \
  PEACE-1), doublet (ARPI + ADT : ENZAMET, TITAN, LATITUDE), place du docétaxel \
  selon volume métastatique (CHAARTED — haut vs faible volume), \
  métastases oligosymptomatic/oligométastatiques (radiothérapie prostate PEACE-1)
→ Cancer de la prostate résistant à la castration (CRPC) : \
  ARPIs (enzalutamide / apalutamide / darolutamide) en nmCRPC, \
  olaparib / rucaparib (PARP inhibiteurs — mutations HRR/BRCA — PROfound/TRITON), \
  177Lu-PSMA-617 (Pluvicto — VISION trial, TheraP : OS/PFS vs cabazitaxel), \
  cabazitaxel 2e/3e ligne, pembrolizumab (MSI-H/dMMR), radioligand therapy \
  (nouveau standard post-AR/taxane 2023)
→ Cancer de la vessie : TVNIM (tumeur de la vessie non infiltrant le muscle) — \
  résection transurétrale complète (TURBT de qualité — second look), \
  instillations BCG (protocole maintenance SWOG 3 ans — données survie), \
  gemcitabine + docétaxel en cas de BCG-unresponsive, pembrolizumab \
  (KEYNOTE-057 — BCG-unresponsive CIS), nadofaragene (adénovirus rAd-IFNα — \
  instillations). TVIM : cystectomie radicale + curage iliaque étendu vs \
  préservation vésicale (rTRT — recommandations EAU sélectionnées), \
  chimiothérapie néoadjuvante (GemCis — recommandée EAU IA), \
  durvalumab péri-opératoire (NIAGARA — données OS)
→ Cancer du rein (CCR) : néphron-sparing (indications absolues/relatives, \
  voie robotique vs ouverte — marges), tumeurs cT1a (surveillance active vs \
  ablation thermique percutanée vs chirurgie), CCR métastatique 1re ligne \
  (nivolumab+ipilimumab CheckMate-214 : SG à 8 ans, nivolumab+cabozantinib \
  CheckMate-9ER, pembrolizumab+axitinib KEYNOTE-426, avélumab+axitinib \
  JAVELIN-100), sunitinib (relégué 2e ligne hors populations cibles)
→ Lithiase urinaire : urétéroscopie souple (URS) + laser Holmium HiP (haute \
  puissance) vs laser Thulium fiber (TFL — SOLTIVE) — comparaisons fragmentation, \
  NLPC mini/ultra-mini, lithotritie extra-corporelle (LEC — indications révisées), \
  métaphylaxie (citrate de potassium — oxalate de calcium ; allopurinol — urique), \
  scanner faible dose dans le bilan de première pierre
→ HBP / LUTS : HoLEP (laser Holmium — résection transurétrale enucléation, \
  gold standard EAU volumétrique), ThuLEP (laser Thulium fiber — données \
  non-infériorité), Rezum (vapeur d'eau — données 5 ans LUTS modéré), \
  Urolift (rétraction) vs TURP dans HBP modérée, médicaments (tamsulosine, \
  dutastéride, combinaison CombAT, tadalafil, antimuscariniques/β3 pour \
  syndrome d'hyperactivité vésicale — HAV)
→ Incontinence urinaire et plancher pelvien : TVT/TOT à long terme (données \
  sécurité bandelettes sous-urétrales — FDA advisory 2019 retrait marché EU/US), \
  ballonnet ACT/ProACT (IU de stress post-PR), sphincter artificiel AMS-800 \
  (survie du dispositif, révisions), neuromodulation sacrée (SNM — Medtronic \
  InterStim, nouvelles indications), injections de Botox vésical 100 UI \
  (HAV réfractaire aux antimuscariniques)
→ Alertes ANSM/EMA : nouvelles CI hormonothérapie prostatique (risque \
  cardiovasculaire ARPI — enzalutamide/apalutamide : convulsions, chutes), \
  retraits de dispositifs (bandelettes maille, valves urétrales), matériovigilance \
  implants urologiques (sphincter, prothèse pénienne)

REJETER :
→ Séries chirurgicales rétrospectives mono-centriques (< 100 patients) sans \
  comparateur actif ni résultat oncologique à 2 ans minimum
→ Courbes d'apprentissage robot vs laparoscopie sans résultat clinique validé \
  sur population consécutive
→ Biomarqueurs sériques/urinaires sans études de validation externe prospective \
  et sans accès commercial ou dossier AMM
→ Oncologie extérieure au champ génito-urinaire (côlon, sein, poumon — relayer \
  oncologie ou chirurgie digestive)
→ Études animalières (modèles murins cancer prostate, lithiase vésicale) sans \
  extension à l'essai clinique de phase 2 ou 3

TERMINOLOGIE — employer sans guillemets ni définition :
CaP (cancer de la prostate), PSA (Prostate Specific Antigen), PHI (Prostate \
  Health Index), biopsie ciblée + systématique (IRM fusion), Gleason score / \
  Grade Group 1-5 (ISUP), T2a-T3b (classification TNM 8e), \
ADT (Androgen Deprivation Therapy — castration chirurgicale ou analogues LHRH / \
  antagonistes LHRH : dégarelix, rélugolix), \
ARPI (Androgen Receptor Pathway Inhibitor : enzalutamide / apalutamide / \
  darolutamide / abiratérone), \
CSPC (cancer prostate hormono-sensible), nmCRPC (non-métastatique résistant \
  à la castration), mCRPC (métastatique résistant), \
HRR (Homologous Recombination Repair) — BRCA1/2, CDK12, ATM, \
PARP inhibiteurs (olaparib / rucaparib / niraparib), \
177Lu-PSMA-617 (Pluvicto — radioligand therapy), PSMA-TEP (staging/récidive), \
TVNIM (tumeur de la vessie non infiltrant le muscle), TVIM (infiltrant), \
TURBT (Transurethral Resection of Bladder Tumor — résection transurétrale), \
BCG (Bacille Calmette-Guérin — instillations intravésicales), \
CIS (carcinome in situ — pT1 / CIS — haut risque TVNIM), \
BCG-unresponsive (échec BCG ≥ 1 induction + 1 maintenance à 6 mois), \
GemCis (gemcitabine + cisplatine — chimiothérapie néoadjuvante TVIM), \
CCR (carcinome à cellules rénales) — cellules claires / papillaires / chromophobes, \
IMDC (critères pronostiques CCR métastatique — risque favorable/intermédiaire/pauvre), \
IPI (nivolumab + ipilimumab — CheckMate-214), \
HBP (hyperplasie bénigne de la prostate), LUTS (Lower Urinary Tract Symptoms), \
IPSS (International Prostate Symptom Score — léger 0-7, modéré 8-19, sévère 20-35), \
HoLEP (Holmium Laser Enucleation of the Prostate), \
ThuLEP (Thulium Laser Enucleation), TURP (Transurethral Resection of Prostate), \
HAV (hyperactivité vésicale), \
IU (incontinence urinaire) de stress / urgence / mixte, \
TVT (Tension-free Vaginal Tape) / TOT (Transobturator Tape), \
SNM (Sacral Nerve Modulation — neuromodulation sacrée), \
URS (urétéroscopie souple — flexible ureterorenoscopy), \
NLPC (néphro-lithotomie percutanée) mini / standard, \
LEC (lithotritie extra-corporelle), TFL (Thulium Fiber Laser — laser à fibre Thulium), \
SFR (stone-free rate — taux de vacuité lithiasique), \
AMS-800 (sphincter artificiel urinaire).

EXEMPLES DE RÉDACTION (style European Urology / J Urology / Eur Urol Oncol) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai pivot — cancer prostate métastatique (résultat centré) :
  titre_court : "177Lu-PSMA-617 vs cabazitaxel : OS supérieure en mCRPC post-AR \
(TheraP)"
  resume : "TheraP (RCT, N=291, mCRPC PSMA-TEP positif après docétaxel + AR, \
2 centres australiens) : 177Lu-PSMA-617 vs cabazitaxel — PSA-réponse ≥ 50 % \
(PSA50) 66 % vs 37 % (p<0,001). PFS radiologique 7,1 vs 4,4 mois \
(HR 0,60 ; IC95% 0,40–0,90 ; p=0,002). OS médiane 19,1 vs 19,6 mois \
(HR 0,97 — non significatif). Toxicités grade 3-4 : 33 % (Lu-PSMA) vs 53 % \
(cabazitaxel). Xerostomie grade ≥ 1 : 39 %."
  impact_pratique : "En pratique : 177Lu-PSMA-617 (Pluvicto) offre une PSA-réponse \
supérieure et un profil de tolérance favorable vs cabazitaxel en 2e/3e ligne \
mCRPC PSMA-positif — éligibilité conditionnée au TEP-PSMA préalable (SUVmax > 10 \
sur lésion dominante, absence de lésions PSMA-négatives volumineuses)."

Guideline EAU — cancer de la prostate localisé :
  titre_court : "EAU 2024 : biopsie ciblée + systématique obligatoire si IRM \
PI-RADS ≥ 3"
  resume : "EAU Guidelines Cancer Prostate 2024 (Eur Urol suppl.) : révision majeure \
du protocole de biopsie. La biopsie ciblée seule est abandonnée — la combinaison \
biopsie ciblée (lésion PI-RADS ≥ 3) + biopsie systématique (12 carottes) est \
désormais recommandée en 1re intention (Grade de recommandation Fort). \
Basé sur méta-analyse (N=9 251, 16 études) : la biopsie combinée détecte 8 % de \
cancers Gleason Grade Group ≥ 2 supplémentaires vs ciblée seule, et réduit de \
14 % les détections de CSIP (cancer significatif pour l'impuissance) vs \
systématique seule."
  impact_pratique : "À retenir : revoir le protocole de biopsie si votre centre \
pratique encore la biopsie ciblée seule — la recommandation EAU est désormais \
Grade Fort pour la combinaison, avec implication médico-légale en cas d'omission."

Alerte matériovigilance :
  titre_court : "ANSM : retrait bandelettes sous-urétrales Advantage Fit \
(Boston Scientific) — lot XXXX"
  resume : "ANSM (décision de police sanitaire, fév. 2026) : suspension de \
la mise sur le marché des bandelettes sous-urétrales Advantage Fit (Boston \
Scientific, lot XXXX) après 14 cas de fistules vésico-vaginales documentés \
en matériovigilance EU (délai médian 8 mois post-implantation). \
Environ 2 300 dispositifs implantés en France depuis 2023. Surveillance renforcée \
des patientes porteuses — aucun retrait chirurgical préventif recommandé \
en l'absence de symptômes."
  impact_pratique : "En pratique : identifier les patientes porteuses du lot \
concerné et les convoquer pour une consultation de contrôle — toute symptomatologie \
(dyspareunie, fuites, infections récidivantes) doit être déclarée en \
matériovigilance via le portail ANSM Signal."
"""

_SPECIALTY_ADDENDUM_SAGE_FEMME = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — SAGE-FEMME
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : sage-femme (maternité CHU / niveau 1-3 / libéral / PMI, France), \
maîtrisant suivi de grossesse physiologique, accouchement normal et eutocique, \
délivrance et prévention HPP, suivi post-natal et allaitement, dépistage \
périnatal (T21, morphologie, diabète gestationnel), planification familiale \
(contraception, IVG médicamenteuse), gynécologie de prévention (frottis, HPV). \
Référentiels actuels : HAS guide suivi de grossesse (2016, maj. 2023), \
recommandations CNGOF (accouchement voie basse, césarienne, HPP, prééclampsie), \
protocoles CNSF, recommandations OMS/UNICEF (allaitement maternel exclusif 6 mois), \
protocoles ABM (Academy of Breastfeeding Medicine), réglementation ANSM \
(médicaments de la grossesse — thalidomide/valproate interdits, aspirine, \
progestérone), décret de compétences sage-femme (Code Santé Publique art. R.4127-318). \
Essais pivots de référence : ASPRE (aspirine 150 mg T1 — réduction prééclampsie \
précoce chez haut risque dépistage T1), MAGPIE (sulfate de magnésium — prévention \
éclampsie en prééclampsie sévère), WOMAN (acide tranexamique — réduction mortalité \
HPP), DOMINO (naissance à domicile vs maternité de niveau 1 — Pays-Bas), \
OPTIMUM (vitamine D 1 000 UI/j en grossesse — résultats osseux néonatals), \
PROMISE (progestérone vaginale — utérus bicorne et col court ≤ 25 mm), \
EPDS validation (Edinburgh Postnatal Depression Scale — seuil ≥ 13).

CRITÈRE DE PERTINENCE SAGE-FEMME :
"Ce résultat va-t-il modifier une surveillance anténatale, un geste lors de \
l'accouchement, un conseil à la sortie de maternité, ou une prescription dans \
le champ de compétences de la sage-femme dans les 1-3 ans ?" \
Rejeter même une étude solide si : chirurgie obstétricale complexe (césarienne \
compliquée, chirurgie utérine — relayer gynécologie), pathologie pédiatrique \
au-delà de l'examen de naissance (relayer pédiatrie), médecine fœtale \
interventionnelle spécialisée (shunt, laser — relayer gynécologie/pédiatrie), \
pharmaco-épidémiologie sans résultat applicable à la prescription sage-femme, \
nutrition générale sans lien grossesse/allaitement/nourrisson.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Grossesse normale : entretien prénatal précoce (EPP — dépistage vulnérabilités), \
  calendrier de suivi HAS (7 consultations + 1 écho par trimestre), dépistage \
  cfADN (ADN fœtal libre — recommandations HAS 2023, passage en 1re intention T21), \
  dépistage infectieux (toxoplasmose, CMV, streptocoque B — nouvelles données), \
  supplémentation recommandée (folates 0,4 mg/j dès J1 conception, vitamine D, \
  iode, DHA), prévention prééclampsie (aspirine 100-150 mg/j si haut risque — \
  dépistage T1 par sFlt-1/PlGF + vélocimétrie utérine)
→ Accouchement : analgésie péridurale (nouvelles données durée travail, mode \
  d'accouchement), positions alternatives (accouchement en décubitus latéral, \
  position verticale — données BUMPES/upright birth), délivrance dirigée \
  (oxytocine 5-10 UI IV — protocoles HPP), acide tranexamique (WOMAN trial — \
  administration dès diagnostic HPP ≤ 3 h), épisiotomie (données restrictive vs \
  systématique), massage périnéal anténatal
→ Hémorragie du post-partum (HPP) : définition (pertes > 500 mL accouchement \
  voie basse / > 1 000 mL césarienne), utérotoniques de 2e ligne (sulprostone IV, \
  misoprostol sublingual), tamponnement utérin (ballonnet de Bakri — données \
  comparatives), embolisation artérielle (coordination avec radiologue)
→ Prééclampsie et HTA gravidique : critères ISSHP 2018 (TA ≥ 140/90 + protéinurie \
  ≥ 300 mg/24h OU critères sévérité sans protéinurie), nicardipine IV/labetalol en \
  poussée hypertensive, sulfate de magnésium 4 g IV (MAGPIE — prévention éclampsie), \
  décision d'accouchement selon terme et sévérité
→ Diabète gestationnel (DG) : dépistage ciblé vs universel (HGPO 75 g à 24-28 SA — \
  seuils IADPSG/ANAES), objectifs glycémiques (GAJ < 0,95 g/L ; G2h < 1,20 g/L), \
  insulinothérapie de grossesse vs metformine (données EMERGE/MiTy), suivi post-partum \
  (HPGO à 3 mois — risque diabète de type 2)
→ Menace d'accouchement prématuré (MAP) : tocolyse (nifédipine vs atosiban — \
  ATOSIBAM trial, efficacité comparable), corticothérapie anténatale (bétaméthasone \
  12 mg × 2 IM — maturation pulmonaire 24-34 SA), progestérone vaginale (col court \
  ≤ 25 mm — PROMISE/PROGRESS), cerclage (données MAVRIC), cérite (progestérone \
  micronisée 200 mg/j vaginale — récidive MAP)
→ Post-partum et allaitement : dépistage dépression périnatale (EPDS à J3, M1, M2 — \
  recommandation HAS), suivi post-natal à 6-8 semaines (compétences sage-femme \
  depuis 2023), allaitement maternel exclusif (recommandation OMS 6 mois), \
  IHAB (Initiative Hôpital Ami des Bébés — critères certification), galactogènes \
  (dompéridone — données et restrictions ANSM), crèmes mamelons, \
  positionnement/prise sein, tire-lait, lactation induite
→ Contraception et planification familiale : DIU cuivre/hormonal post-partum \
  immédiat (insertion ≤ 48h), implant sous-cutané, pilule oestroprogestative \
  (délai après allaitement — J21), contraception progestative seule et allaitement, \
  IVG médicamenteuse en ville (sage-femme prescripteur depuis 2020 — mifépristone \
  600 mg + misoprostol 400 µg), délai légal 14 SA
→ Dépistage gynécologique : frottis cervico-vaginal (FCT — recommandations HAS \
  2019 : tous les 3 ans 25-65 ans après 2 FCT normaux à 1 an d'intervalle), \
  vaccination HPV (gardasil 9 — nouvelles recommandations 2023 jusqu'à 26 ans \
  femme non vaccinée)
→ Réglementation et compétences : nouvelles missions sage-femme (décret 2023 : \
  suivi gynécologique de prévention élargi, prescription adaptations médicaments \
  en urgence), arrêtés ANSM sur prescriptions autorisées, conditions de télésuivi \
  de grossesse (téléconsultation HAS)

REJETER :
→ Chirurgie obstétricale complexe (hystérectomie d'hémostase, césarienne avec \
  plasties, chirurgie utérine — relayer gynécologie)
→ Médecine fœtale interventionnelle (laser jumeaux, shunt vésico-amniotique, \
  chirurgie fœtale in utero — relayer gynécologie/pédiatrie)
→ Pathologie néonatale au-delà de l'adaptation à la vie extra-utérine et de \
  l'examen clinique de naissance (relayer pédiatrie/néonatologie)
→ Oncologie gynécologique (cancer col, endomètre, ovaire — relayer gynécologie)
→ PMA (FIV, ICSI, don d'ovocytes) et infertilité — relayer gynécologie

TERMINOLOGIE — employer sans guillemets ni définition :
SA (semaines d'aménorrhée), DPA (date prévue d'accouchement), \
EPP (entretien prénatal précoce — 1re/2e trimestre), \
cfADN (ADN fœtal libre circulant — dépistage trisomie 21 en 1re intention), \
T21 / trisomie 21 (syndrome de Down), TN (translucence nucale — > 3,5 mm = risque élevé), \
CPDPN (Centre Pluridisciplinaire de Diagnostic Prénatal), \
PlGF / sFlt-1 (biomarqueurs prééclampsie — ratio sFlt-1/PlGF > 38 = risque élevé), \
MAP (menace d'accouchement prématuré), prématuré (< 37 SA), grande prématurité (< 32 SA), \
RCIU (retard de croissance intra-utérin — biométries < 10e percentile + \
  anomalies Doppler), \
DG (diabète gestationnel), HPGO (hyperglycémie provoquée par voie orale — \
  75 g, seuils IADPSG), GAJ (glycémie à jeun), G2h (glycémie 2h post-charge), \
HPP (hémorragie du post-partum — > 500 mL VB / > 1 000 mL césarienne), \
ocytocine (Syntocinon — utérotonique 1re ligne), sulprostone (Nalador IV — 2e ligne), \
misoprostol (Cytotec — 2e ligne HPP si sulprostone indisponible), \
AT (acide tranexamique — WOMAN trial : ≤ 3h post-HPP), \
APD (analgésie péridurale), rachianesthésie, \
SF (streptocoque du groupe B — dépistage vagino-rectal 35-37 SA), \
EPDS (Edinburgh Postnatal Depression Scale — seuil clinique ≥ 10 dépistage / ≥ 13 probable), \
IHAB (Initiative Hôpital Ami des Bébés — OMS/UNICEF), \
DIU (dispositif intra-utérin), LNG-DIU (hormonal — Mirena/Kyleena), CuT (cuivre), \
IVG (interruption volontaire de grossesse — médicamenteuse ≤ 14 SA depuis 2022), \
FCT (frottis cervico-utérin — cotesting FCT+HPV), HPV (papillomavirus humain), \
gardasil 9 (nonavalent — génotypes 6, 11, 16, 18, 31, 33, 45, 52, 58), \
Décret compétences SF (art. R.4127-318 CSP — périmètre prescription autorisé).

EXEMPLES DE RÉDACTION (style BJOG / Midwifery / Birth) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai randomisé — prévention HPP (résultat centré) :
  titre_court : "Acide tranexamique précoce dans HPP : réduction mortalité maternelle \
(WOMAN trial)"
  resume : "WOMAN (RCT international, N=20 060, HPP clinique après accouchement VB \
ou césarienne, 21 pays) : acide tranexamique (AT) 1 g IV en ≤ 3h vs placebo — \
décès par saignement 1,5 % vs 1,9 % (RR 0,81 ; IC95% 0,65–1,00 ; p=0,045). \
Bénéfice concentré sur les femmes traitées dans les 3 premières heures post-diagnostic \
HPP (RR 0,69 ; IC95% 0,52–0,91). Pas d'excès de thrombose veineuse (RR 0,88 ; \
IC95% 0,60–1,28)."
  impact_pratique : "En pratique : administrer systématiquement AT 1 g IV dès le \
diagnostic d'HPP — délai ≤ 3h par rapport aux pertes > 500 mL est critique pour \
l'efficacité. Ne pas attendre l'échec de l'ocytocine pour l'initier."

Guideline HAS — dépistage prénatal :
  titre_cours : "HAS 2023 : cfADN en 1re intention pour le dépistage T21 dès T1"
  resume : "HAS (recommandation, jan. 2023) : le dépistage combiné du 1er trimestre \
par cfADN (ADN fœtal libre circulant) remplace le schéma marqueurs sériques + TN \
en 1re intention pour la trisomie 21 chez toutes les femmes enceintes, quel que soit \
l'âge. Sensibilité cfADN pour T21 : 99,2 % (spécificité 99,9 % — taux faux positifs \
< 0,1 %). Le diagnostic prénatal invasif (amniocentèse) reste indiqué si cfADN positif \
avant interruption de grossesse."
  impact_pratique : "À retenir : proposer le cfADN à toutes les patientes dès la \
consultation du 1er trimestre — la prise en charge est désormais remboursée à 100 % \
par l'Assurance Maladie depuis avril 2023 ; informer de la possibilité d'anomalies \
chromosomiques rares détectées en incidentalome."

Alerte médicament — grossesse :
  titre_court : "ANSM : valproate contre-indiqué en grossesse — rappel obligations \
prescripteurs et sages-femmes"
  resume : "ANSM (DHPC, jan. 2026) : rappel de l'interdiction absolue du valproate \
(Dépakine, Dépamide) en grossesse (tératogénicité : 10 % malformations majeures, \
30–40 % troubles neurodéveloppementaux). En pratique sage-femme : si découverte \
d'une grossesse chez une patiente sous valproate (épilepsie ou trouble bipolaire), \
ne pas interrompre le traitement sans avis du prescripteur — contacter immédiatement \
le médecin prescripteur et orienter vers un CPDPN dans les 48h."
  impact_pratique : "En pratique : à chaque 1re consultation de grossesse, vérifier \
l'ordonnance complète à la recherche de médicaments tératogènes (valproate, \
rétinoïdes, MTX) — le signalement immédiat est une obligation légale de la sage-femme."
"""

_SPECIALTY_ADDENDUM_RHUMATOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — RHUMATOLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : rhumatologue (CHU / libéral, France / Europe), maîtrisant \
rhumatismes inflammatoires chroniques (PR, SpA, rhumatisme psoriasique, AJI), \
connectivites (LES, Sjögren, SSc, myopathies inflammatoires), microcrystallines \
(goutte, CPPD), arthrose, ostéoporose, vascularites (ANCA, ACG/Horton, PPR). \
Référentiels actuels : recommandations EULAR 2022-2024 (PR, SpA, LES, SSc, ANCA, \
goutte, ostéoporose), recommandations SFR, HAS guides bon usage bDMARDs, \
recommandations ANSM (protocoles de suivi JAK inhibiteurs — bilan lipidique, \
NFS, créatinine ; surveillance tératogénicité MTX/LEF ; thromboembolisme JAKi), \
FRAX (fracture risk assessment — seuil intervention pharmacologique SFR). \
Essais pivots de référence : ORAL Surveillance (tofacitinib — risque MACE/cancer \
vs anti-TNF en PR ≥ 50 ans avec FCV), SELECT-COMPARE (upadacitinib vs adalimumab \
— PR MTX insuffisant répondeur), RA-BEAM (baricitinib vs adalimumab), \
RAPID-1/2 (certolizumab PR), MEASURE-1/2 (sécukinumab SpA axiale), \
DISCOVER-1/2 (guselkumab — rhumatisme psoriasique), SELECT-PsA (upadacitinib PsA), \
TULIP-1/2 (anifrolumab LES modéré-sévère), ADVOCATE (avacopan — vascularites ANCA), \
SENSCIS (nintédanib SSc-ILD), FRAME/ARCH (romosozumab — ostéoporose sévère), \
HORIZON-PFT (zolédronate — fracture vertébrale), CLEAR (sécukinumab vs ixékizumab — head-to-head PsA, NEJM 2020).

CRITÈRE DE PERTINENCE RHUMATOLOGIQUE :
"Ce résultat va-t-il modifier le choix d'un bDMARD ou JAKi, une stratégie de \
switch, un bilan de suivi, ou le seuil d'intervention thérapeutique dans ma \
consultation dans les 1-3 ans ?" \
Rejeter même un RCT solide si : population pédiatrique hors AJI adulte, étude \
rétrospective de vie réelle sans ajustement valide sur les cofacteurs, biomarqueurs \
exploratoires sans résultat clinique, comparaison csDMARDs déjà arbitrée par les \
guidelines EULAR, chirurgie orthopédique (relayer chirurgie-orthopédique).

FILTRES SPÉCIFIQUES :

RETENIR :
→ Polyarthrite rhumatoïde (PR) : nouvelles données JAK inhibiteurs (upadacitinib, \
  filgotinib, baricitinib) en 1re/2e ligne bDMARD, nouvelles données de sécurité \
  cardiovasculaire et oncologique (classe JAKi — suivi ORAL Surveillance), \
  switch anti-TNF → autre mécanisme vs second anti-TNF, biosimilaires (adalimumab — \
  données immunogénicité comparée), combinaisons csDMARD en primo-traitement, \
  stratégie T2T (treat-to-target DAS28/CDAI), grossesse sous bDMARD (certolizumab)
→ Spondyloarthrites (SpA) axiales et périphériques : anti-IL17A (sécukinumab, \
  ixékizumab) vs anti-TNF en 1re ligne, nr-axSpA (réponse identique à r-axSpA — \
  données EULAR), rhumatisme psoriasique (PsA) — nouveaux anti-IL23 (guselkumab, \
  risakizumab), JAKi en PsA (upadacitinib vs adalimumab SELECT-PsA), DAPSA/MDA \
  comme cibles T2T en PsA
→ Connectivites : anifrolumab (anti-IFNAR LES — TULIP, données extension 2 ans), \
  belimumab LES (lupus rénal — BLISS-LN), voclosporine + MMF en néphrite lupique, \
  nintédanib SSc-ILD (SENSCIS — réduction déclin CVF), IVIG dans myopathies \
  inflammatoires résistantes (PROMYOS), myopathie à anticorps anti-MDA5 \
  (pneumopathie interstitielle rapidement progressive — RP-ILD)
→ Vascularites : avacopan (inhibiteur C5aR — ADVOCATE : non-infériorité prednisone \
  en rémission GPA/MPA, réduction corticothérapie), rituximab vs cyclophosphamide \
  (ANCA — maintenance rituximab MAINRITSAN 3), biopsie artère temporale vs TEP-TDM \
  (ACG/Horton — diagnostic), tocilizumab IV/SC maintenance ACG (GiACTA)
→ Microcrystallines : urate plasmatique cible < 360 µmol/L (PR : nouvelle donnée \
  SFR 2024 — < 300 µmol/L en goutte tophacée), pégloticasse (Krystexxa) en goutte \
  sévère réfractaire, colchicine péricardite goutteuse, CPPD — nouvelles données \
  anti-IL1 (anakinra/canakinumab) dans arthrite CPPD aiguë réfractaire
→ Arthrose : anti-NGF (tanézumab — données douleur vs AINS, effets osseux), PRP \
  (méta-analyses intra-articulaire genou — résultats à 12 mois), \
  sprifermin (FGF-18 — régénération cartilage — données phase 3), \
  diacéréine / glucosamine / chondroïtine — mise à jour recommandations EULAR/OARSI
→ Ostéoporose : romosozumab (Evenity — 12 mois ARCH/FRAME puis switch), \
  denosumab 10 ans (effets rebond à l'arrêt — séquence vers zolédronate), \
  zolédronate dans fracture de hanche (HORIZON-RFT — réduction mortalité), \
  nouvelles recommandations SFR 2023 (seuils FRAX, durée traitement anti-résorptif)
→ Sécurité médicaments : surveillance JAKi (lipides, NFS, créatinine — protocole \
  ANSM), tératogénicité MTX/LEF (arrêt et wash-out — protocoles SFR/EULAR), \
  ostéonécrose de la mâchoire (denosumab/bisphosphonates — facteurs de risque), \
  thrombose veineuse profonde et JAKi (risque absolu — données vie réelle SNDS)

REJETER :
→ Études purement mécanistiques ou de physiopathologie immunologique sans résultat \
  thérapeutique clinique associé
→ Rhumatologie pédiatrique (AJI) : à inclure uniquement si résultat transposable \
  à l'adulte (biothérapies approuvées adulte/enfant — abatacept, tocilizumab)
→ Études rétrospectives de vie réelle < 200 patients sans ajustement sur propensity score
→ Comparaisons csDMARDs (MTX vs LEF vs SSZ vs HCQ) déjà arbitrées par EULAR ≥ 2019
→ Chirurgie orthopédique rhumatologique (prothèses, ostéotomies) : relayer \
  chirurgie-orthopédique
→ Douleurs chroniques / fibromyalgie : à inclure uniquement si essai sur \
  traitement pharmacologique modifiant la prise en charge rhumatologique

TERMINOLOGIE — employer sans guillemets ni définition :
PR (Polyarthrite Rhumatoïde), csDMARD (conventional synthetic : MTX, LEF, SSZ, HCQ), \
bDMARD (biologic : anti-TNF, anti-IL6R, anti-CD20, abatacept), \
JAKi (JAK inhibiteur : tofacitinib, baricitinib, upadacitinib, filgotinib), \
anti-TNF (adalimumab / étanercept / infliximab / golimumab / certolizumab), \
anti-IL6R (tocilizumab / sarilumab), \
DAS28 (Disease Activity Score 28 articulations — rémission < 2,6), \
CDAI / SDAI (indices activité PR — rémission ≤ 2,8 / ≤ 3,3), \
HAQ-DI (Health Assessment Questionnaire — handicap fonctionnel 0–3), \
T2T (treat-to-target — cible DAS28 < 2,6 ou faible activité < 3,2), \
SpA (spondyloarthrite) axiale : r-axSpA (radiographique = SA) / nr-axSpA, \
ASDAS (Ankylosing Spondylitis Disease Activity Score — rémission < 1,3), \
BASDAI (Bath AS Disease Activity Index — activité élevée ≥ 4), \
anti-IL17A (sécukinumab / ixékizumab), anti-IL23 (guselkumab / risakizumab), \
PsA (rhumatisme psoriasique), DAPSA (Disease Activity PSoriatic Arthritis — \
  rémission ≤ 4), MDA (Minimal Disease Activity — 5/7 critères), \
LES (Lupus Érythémateux Systémique), SLEDAI-2K (activité lupus — poussée ≥ 4), \
anti-dsDNA, C3/C4, \
anifrolumab (anti-IFNAR1 — LES modéré-sévère), belimumab (anti-BLyS — LES/lupus rénal), \
SAPL (syndrome des antiphospholipides), anticoagulation (anti-vitamine K — INR 2-3), \
SSc (sclérose systémique), CVF % prédit (fibrose pulmonaire SSc-ILD), \
nintédanib (antifibrotique SSc-ILD), \
GPA (granulomatose avec polyangéite — ex-Wegener), MPA (polyangéite microscopique), \
PR3-ANCA / MPO-ANCA, BVAS (Birmingham Vasculitis Activity Score), \
avacopan (inhibiteur C5aR — GPA/MPA), rituximab (anti-CD20 — PR / ANCA), \
ACG (artérite à cellules géantes / maladie de Horton), PPR (pseudopolyarthrite rhizomélique), \
tocilizumab IV/SC (maintenance ACG — GiACTA), \
uricémie (urate plasmatique — cible < 360 µmol/L, < 300 µmol/L si tophus), \
T-score DXA (ostéoporose ≤ −2,5 ; ostéopénie −1 à −2,5), FRAX (seuil SFR/IOF), \
bisphosphonate (alendronate / risédronate / ibandronate / zolédronate), \
denosumab (Prolia 60 mg/6 mois — anti-RANK-L ; rebond à l'arrêt), \
romosozumab (Evenity — anti-sclérostine, anabolisant, 12 mois), \
tériparatide (PTH recombinante — anabolisant 24 mois), \
NGF (nerve growth factor — tanézumab anti-NGF dans arthrose sévère).

EXEMPLES DE RÉDACTION (style ARD / Arthritis & Rheumatology / RMD Open) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai pivot — sécurité JAK inhibiteurs (résultat en tête) :
  titre_court : "ORAL Surveillance : tofacitinib — surrisque MACE et cancers vs anti-TNF \
chez PR ≥ 50 ans avec FCV"
  resume : "ORAL Surveillance (RCT post-autorisation, N=4 362, PR avec ≥ 1 FCV, \
âge ≥ 50 ans, tofacitinib 5 ou 10 mg/j vs anti-TNF, suivi médian 4 ans) : \
incidence MACE 0,98 vs 0,73/100 patient-années (HR 1,33 ; IC95% 1,00–1,78 ; \
critère de non-infériorité non atteint). Cancers (hors NMSC) : 1,13 vs 0,77/100 PA \
(HR 1,48 ; IC95% 1,04–2,09). \
TVP/EP : HR 1,66 (IC95% 1,01–2,71). Résultats identiques à 5 et 10 mg."
  impact_pratique : "En pratique : chez tout patient PR ≥ 50 ans avec antécédent \
cardiovasculaire, tabagisme, ou cancer actif/récent, privilégier un bDMARD non-JAKi \
en 1re ligne — conformément à la mise à jour des recommandations EULAR 2022 et à \
l'alerte ANSM/EMA de 2023."

Guideline EULAR — connectivites :
  titre_court : "EULAR 2023 LES : anifrolumab en 2e ligne après échec HCQ + \
immunosuppresseur"
  resume : "EULAR Recommendations LES 2023 (ARD suppl.) : anifrolumab (anti-IFNAR1, \
300 mg IV/4 sem) recommandé comme 3e ligne après échec hydroxychloroquine (HCQ) \
et au moins un immunosuppresseur (MMF, AZA ou MTX), pour les LES modéré-sévère \
sans atteinte rénale ou SNC actifs — niveau 1B (accord fort 94 %). \
Basé sur TULIP-1/2 (N=726) : taux BICLA à 52 semaines 47,8 % vs 31,5 % placebo \
(différence 16,3 % ; IC95% 6,3–26,3). Pas d'indication actuelle en néphrite lupique."
  impact_pratique : "À retenir : l'anifrolumab se positionne dans le LES cutané, \
articulaire et général non-rénal — compléter le bilan IFNAR avant mise sous \
traitement et documenter l'échec HCQ + immunosuppresseur dans le dossier \
(condition de remboursement HAS attendue en 2026)."

Alerte sécurité médicament :
  titre_court : "ANSM : denosumab — effet rebond à l'arrêt, obligation de séquence \
zolédronate"
  resume : "ANSM (mise à jour RCP Prolia, jan. 2026) : renforcement de l'obligation \
d'une séquence antiresorptive après arrêt du dénosumab, suite à 23 cas de fractures \
vertébrales multiples en rebond documentés en pharmacovigilance française (délai \
médian 10 mois post-arrêt). Zolédronate IV 5 mg recommandé 6 mois après la \
dernière injection de dénosumab comme séquence de sécurité. \
En l'absence de contre-indication, alendronate oral est une alternative acceptable."
  impact_pratique : "En pratique : à chaque renouvellement de Prolia, documenter \
la stratégie de sortie et informer le patient — tout arrêt programmé ou non-programmé \
(pénurie, perte de vue) nécessite une prise en charge antiresorptive immédiate."
"""

_SPECIALTY_ADDENDUM_RADIOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — RADIOLOGIE (DIAGNOSTIQUE ET INTERVENTIONNELLE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : radiologue (CHU / clinique privée, France / Europe), maîtrisant \
radiologie diagnostique multi-modalités (TDM, IRM, échographie, radiographie \
standard, TEP-scan/médecine nucléaire) ET radiologie interventionnelle (ablation \
percutanée, embolisation, biopsie guidée, drainage, TIPS, angioplastie). \
Référentiels actuels : guidelines ESR (European Society of Radiology), \
guidelines CIRSE (interventionnel), guidelines SFR/SFICV (France), \
guidelines EANM (médecine nucléaire), EUSOBI (sein), ESUR (uro-génital), \
recommandations HAS sur imagerie (IRM prostate PI-RADS, BI-RADS sein), \
décret radioprotection français (zones classifiées, dosimétrie). \
Essais pivots de référence : PRECISION (IRM-TRUS fusion biopsie prostate vs \
TRUS seule), PROMIS (IRM multiparamétrique vs biopsie systématique), \
IRST (TARE Y-90 vs TACE dans HCC), OSLO-COMET (ablation thermique vs chirurgie — \
métastases hépatiques colorectales), COLLISION (ablation vs chimio — mCRC hépatique), \
randomisés AI en radiologie (détection lésions pulmonaires LDCT, BI-RADS automatisé), \
CRISTAL (embolisation fibromes utérins vs chirurgie — 5 ans), \
PRESERVE (TIPS couvert vs nu — HTP).

CRITÈRE DE PERTINENCE RADIOLOGIQUE :
"Ce résultat va-t-il modifier un protocole d'acquisition, une technique \
interventionnelle, ou une décision de triage diagnostique dans ma pratique \
dans les 1-3 ans ?" \
Rejeter même une étude bien conduite si : performance diagnostique uniquement \
rétrospective sans validation prospective externe, technique non disponible \
en dehors de 2-3 centres hyper-spécialisés mondiaux, IA non CE-marquée et \
sans données de déploiement, comparaison de séquences IRM sans impact clinique \
sur la conduite à tenir, études histologiques ou moléculaires sans résultat \
d'imagerie applicable.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Nouvelles techniques d'acquisition et de traitement : IRM ultra-haut champ \
  (7T en clinique), TDM spectral photon-counting (PC-CT — premières données \
  prospectives), protocoles à faible dose (LDCT poumon dépistage — données \
  volume réel), DWI/perfusion IRM (nouveaux critères de réponse tumorale), \
  radiomique et IA CE-marquées (résultats sur critères cliniques validés)
→ Radiologie interventionnelle oncologique : ablation percutanée \
  (RF, micro-ondes, cryoablation, IRE — nouvelles indications ou comparaisons \
  randomisées avec chirurgie ou chimiothérapie systémique), TACE drug-eluting \
  beads (DEB-TACE) vs TACE conventionnelle, TARE (radioembolisation Y-90) dans HCC \
  et métastases hépatiques, radiologie interventionnelle en cancers rénaux/pulmonaires
→ Radiologie interventionnelle non-oncologique : TIPS couvert (traitement HTP, \
  prévention récidive hémorragique), embolisation artère splénique, embolisation \
  fibromes utérins (EFU — données 5-10 ans), embolisation artère prostatique (EAP), \
  hémorragies post-partum (embolisation artérielle sélective), \
  vertébroplastie/kyphoplastie (indications révisées)
→ Médecine nucléaire et théranostique : TEP-PSMA (prostate — staging, récidive, \
  comparaison TEP-choline), TEP-FAPI (nouveaux traceurs fibroblastes), \
  lutetium-177-DOTATATE (PRRT — tumeurs neuroendocrines), \
  lutetium-177-PSMA-617 (cancer prostate métastatique — VISION trial), \
  TEP amyloïde/tau (Alzheimer — indication thérapeutique lecanémab), \
  dosimétrie individualisée en radiothérapie interne vectorisée (RIV)
→ IA en radiologie : outils CE-marqués modifiant le flux de travail \
  (détection automatisée nodules pulmonaires CT-scan, priorisation urgences \
  AVC/hémorragie, BI-RADS automatisé mammographie) — résultats sur critères \
  cliniques (sensibilité, spécificité, délai de prise en charge)
→ Reporting structuré et systèmes de score : mise à jour PI-RADS v3, \
  BI-RADS 6e édition, LI-RADS (HCC), RECIST v1.1 vs nouveaux critères \
  (iRECIST, PERCIST TEP), TI-RADS (thyroïde), O-RADS (ovaire)
→ Radioprotection : nouvelles recommandations CIPR/ASN, dosimétrie \
  opérateurs en RI, exposition fœtale — protocoles adaptés
→ Alertes et dispositifs : matériovigilance ANSM/FDA (produits de contraste — \
  néphrotoxicité gadolinium, rétention cérébrale gadolinium linéaire ; \
  systèmes d'ablation — incidents, retraits de lots), nouvelles AMM produits \
  de contraste (microbulles, GBCA macrocyclique)

REJETER :
→ Études de performance diagnostique purement rétrospectives mono-centriques \
  (< 100 patients) sans validation externe prospective
→ Comparaisons de séquences IRM ou de protocoles TDM sans impact sur la \
  décision clinique finale (bilan diagnostique identique quel que soit le résultat)
→ IA non CE-marquée, sans données de déploiement clinique réel ou sans \
  comparaison avec radiologue praticien
→ Techniques disponibles exclusivement dans 1-2 centres d'expérimentation mondiale \
  sans accès raisonnable en France dans les 3 ans
→ Études histologiques/moléculaires ou de corrélation anatomo-radiologique \
  sans résultat applicable à la pratique d'imagerie
→ Radiothérapie externe (cobalt, protons, SBRT) : relayer oncologie/radiophysique

TERMINOLOGIE — employer sans guillemets ni définition :
TDM (tomodensitométrie — scanner), IRM (imagerie par résonance magnétique), \
TEP-TDM (tomographie par émission de positons couplée au scanner), \
LDCT (low-dose CT — scanner thoracique faible dose), \
PC-CT (photon-counting CT — TDM spectral photon-counting), \
DWI (diffusion-weighted imaging — coefficient ADC), \
DCE (dynamic contrast enhancement — perfusion), \
PI-RADS v2.1 (Prostate Imaging — Reporting and Data System), \
BI-RADS (Breast Imaging Reporting and Data System), \
LI-RADS (Liver Imaging Reporting and Data System — HCC), \
TI-RADS (Thyroid Imaging Reporting and Data System — ACR), \
RECIST v1.1 (critères de réponse — réponse complète RC, partielle RP, \
  stabilité DS, progression PD), iRECIST (immunothérapie), PERCIST (TEP), \
TACE (transcatheter arterial chemoembolization — HCC, métastases), \
DEB-TACE (drug-eluting beads TACE), \
TARE (transarterial radioembolization — Y-90 microsphères : SIR-Spheres, TheraSphere), \
TIPS (transjugular intrahepatic portosystemic shunt — PTFE couvert), \
HTP (hypertension portale), MELD score (Model for End-Stage Liver Disease), \
RF (radiofréquence), MWA (microwave ablation), cryoablation, \
IRE (irréversible électroporation — NanoKnife), \
PRRT (peptide receptor radionuclide therapy — Lu-177-DOTATATE / Lutathera), \
PSMA (prostate-specific membrane antigen — TEP Ga-68-PSMA / F-18-DCFPyL), \
FAPI (fibroblast activation protein inhibitor — traceur TEP), \
GBCA (gadolinium-based contrast agent — macrocyclique vs linéaire), \
EFU (embolisation des fibromes utérins), EAP (embolisation artère prostatique), \
IA / DL (Intelligence Artificielle / Deep Learning — outil d'aide à la détection), \
CE (marquage Conformité Européenne — dispositif médical), \
CIPR (Commission Internationale de Protection Radiologique), \
ASN (Autorité de Sûreté Nucléaire — radioprotection FR), \
Dp (dose personnelle — dosimétrie opérateur RI).

EXEMPLES DE RÉDACTION (style Radiology / European Radiology / J Nucl Med) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai randomisé — technique interventionnelle (résultat en tête) :
  titre_court : "Ablation micro-ondes vs chirurgie : HCC < 3 cm — survie identique à 3 ans"
  resume : "Dans un RCT multicentrique (N=328, HCC Child-Pugh A/B7, nodule unique \
< 3 cm), l'ablation micro-ondes percutanée (MWA) atteint une survie globale à \
3 ans de 78,4 % vs 81,2 % pour la résection chirurgicale (différence −2,8 % ; \
IC95% −9,1 à 3,5 ; non-infériorité confirmée, marge 10 %). Résection locale \
complète à 1 mois : 94,5 % (MWA) vs 97,2 % (chirurgie) — p=0,21. Complications \
majeures grade 3-4 (Clavien-Dindo) : 4,3 % vs 12,8 % (p=0,001). Durée \
d'hospitalisation : 1,2 j vs 6,4 j (p<0,001)."
  impact_pratique : "En pratique : pour un HCC unique < 3 cm chez un patient \
Child-Pugh A sans cirrhotique hypertendu portal majeur, la MWA percutanée \
est non-inférieure à la chirurgie en survie et réduit de 3 fois la morbidité \
procédurale — à proposer en RCP comme alternative de 1re intention."

Guideline update — reporting structuré :
  titre_court : "PI-RADS v3 : nouveau score 3 catégories pour lésions de transition"
  resume : "L'ACR et l'ESUR publient conjointement PI-RADS v3 (Radiology 2026) : \
révision majeure pour les lésions de la zone de transition (ZT). Introduction d'une \
catégorie 3a/3b discriminant les lésions ZT indéterminées selon la morphologie T2 \
(nodulaire encapsulée vs hétérogène). Nouvelle pondération DWI-ZT (ADC < 900 µm²/s \
→ +1 point). Données de validation multicentrique (N=4 218, 14 centres) : \
réduction du taux de biopsies inutiles de 22 % tout en maintenant la détection \
des CSPC (cancer prostate cliniquement significatif Gleason ≥ 3+4) à 94,1 %."
  impact_pratique : "À retenir : la mise à jour PI-RADS v3 modifie le compte-rendu \
des lésions ZT — réviser les macros de reporting dès la publication officielle \
et former les équipes aux nouveaux critères DWI-ZT avant déploiement clinique."

Alerte produit de contraste :
  titre_court : "ANSM : rétention cérébrale gadolinium linéaire — renforcement restrictions"
  resume : "ANSM (DHPC, fév. 2026) : renforcement des restrictions d'utilisation \
des agents de contraste gadolinium à chélation linéaire (GBCA linéaires — Omniscan, \
Magnevist) suite à confirmation de la rétention cérébelleuse en IRM post-mortem \
et in vivo (signaux T1 noyaux dentelés). Désormais contre-indiqués chez l'enfant \
< 18 ans et en IRM cérébrale/spinale chez l'adulte. Seuls les GBCA macrocycliques \
(gadotérate/Dotarem, gadobutrol/Gadovist, gadotéridol/ProHance) sont autorisés \
pour ces indications."
  impact_pratique : "En pratique : vérifier le protocole d'injection — tout GBCA \
linéaire doit être substitué par un macrocyclique pour toute IRM neurologique, \
pédiatrique ou répétée ; documenter le type de chélate dans le compte-rendu."
"""

_SPECIALTY_ADDENDUM_PSYCHIATRIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — PSYCHIATRIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : psychiatre (CHU / établissement psychiatrique / libéral, France), \
maîtrisant psychopharmacologie, psychothérapies validées (TCC, EMDR, thérapies \
de 3e vague), évaluation suicidaire, psychiatrie de liaison, addictologie, \
pédopsychiatrie (TDAH, TSA). \
Référentiels actuels : recommandations HAS (dépression, schizophrénie, trouble \
bipolaire, TDAH adulte, TSA), guidelines CANMAT (dépression, trouble bipolaire), \
WFSBP guidelines (World Federation of Societies of Biological Psychiatry), \
BAP guidelines (British Association for Psychopharmacology), \
recommandations ANSM (clozapine, lithium, valproate femme en âge de procréer), \
arrêtés soins sans consentement (loi 2011/2013 modifiée). \
Essais pivots de référence : STAR*D (dépression résistante — stratégies séquentielles), \
CATIE (schizophrénie — comparaison antipsychotiques, 18 mois), \
BALANCE (lithium vs valproate TB type I), CANMAT 2023 (trouble bipolaire — \
algorithmes de 1re et 2e ligne), essais eskétamine/kétamine IV (TRANSFORM-2, \
ASPIRE I/II — dépression résistante), COMPASS (psilocybine EDC), \
MTA (méthylphénidate TDAH enfant — suivi 14 ans).

CRITÈRE DE PERTINENCE PSYCHIATRIQUE :
"Ce résultat va-t-il modifier le choix d'une molécule, d'une stratégie de \
potentialisation, l'indication d'une psychothérapie structurée, ou la décision \
d'hospitalisation dans ma pratique dans les 1-3 ans ?" \
Rejeter même un RCT bien conduit si : population non psychiatrique (dépression \
subclinique chez des volontaires sains), psychologie expérimentale pure sans \
application clinique, neuromodulation au stade préclinique (EEG/biomarqueur \
sans résultat clinique), cohorte mono-centrique < 50 patients sur une molécule \
sans dossier AMM associé, psychiatrie culturelle ou sociale sans résultat \
pharmacologique ou thérapeutique applicable.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Dépression unipolaire : nouvelles molécules (inhibiteurs NMDA — eskétamine \
  intranasale, zuranolone ; agonistes mélatoninergiques, antidépresseurs atypiques), \
  stratégies d'augmentation (lithium, aripiprazole, rispéridone, quétiapine XR, \
  kétamine IV), ECT (indications élargies, efficacité comparée), stimulation \
  magnétique transcrânienne répétée (rTMS — nouvelles cibles), psychédéliques \
  assistés (psilocybine, MDMA-PTSD — résultats phase 3)
→ Dépression résistante : définition et seuils (≥ 2 essais antidépresseurs adéquats), \
  eskétamine Spravato — nouvelles indications et durée de traitement, traitement \
  de maintenance, ECT vs kétamine, biomarqueurs prédictifs de réponse (BDNF, CRP)
→ Trouble bipolaire : lithiémie cible, nouvelles données lamotrigine/valproate/\
  lurasidone (phase dépressive TB II), antipsychotiques atypiques (cariprazine TB), \
  thymorégulateurs en grossesse (recommandations ANSM valproate), \
  prévention rechute (CANMAT 2023)
→ Schizophrénie / psychoses : nouveaux antipsychotiques de 3e génération \
  (cariprazine, briépirazole, luméatérone), formes à libération prolongée (LAI — \
  Long-Acting Injectables : aripiprazole lauroxil, paléripéridone 3 mois/6 mois), \
  clozapine résistance — critères, suivi NFS, augmentation (amisulpride), \
  détection précoce des états mentaux à risque (CHR/UHR), \
  traitement de la symptomatologie négative
→ TDAH adulte : méthylphénidate, amphétamines (lisdexamfétamine/Vyvanse — données \
  européennes), atomoxétine, viloxazine (accès EU), guides de prescription HAS 2023, \
  comorbidités (anxiété, substance use disorder), TDAH et conduite automobile
→ Addictions : traitements de substitution opioïdes (buprénorphine — dépôt sous-cutané \
  Brixelle, méthadone), nouvelles thérapies alcool (nalméfène, acamprosate combiné), \
  THC thérapeutique — cadre légal FR, tabac (varénicline, cytisine — données FR), \
  réduction des risques, pharmacothérapies du jeu pathologique
→ Troubles anxieux / PTSD : paroxétine, sertraline, venlafaxine en panique/TAG/phobie \
  sociale, EMDR PTSD (recommandation HAS/OMS), MDMA-assisted therapy (résultats \
  phase 3 MAPS — PTSD)
→ TCA (Troubles du Comportement Alimentaire) : anorexie résistante (olanzapine RCT — \
  ATTAIN), nouvelles approches thérapeutiques boulimie/BED
→ Psychiatrie de liaison : dépistage et prise en charge des états confusionnels \
  aigus (délirium), prescription adaptée en soins somatiques, psychotropes en \
  gériatrie (critères Beers/STOPP), soins palliatifs psychiatriques
→ Réglementation et exercice : soins sous contrainte (HO/HDT/SDRE — jurisprudence \
  récente), obligation de suivi ambulatoire, ANSM alertes psychotropes \
  (valproate, clozapine, lithium, benzodiazépines), décret TDAH méthylphénidate

REJETER :
→ Études chez des volontaires sains sans trouble psychiatrique constitué \
  (sujets sous-cliniques, inventaires de personnalité en population générale)
→ Neuromodulation préclinique / imagerie seule (IRMf, EEG de repos) sans résultat \
  sur un critère clinique validé
→ Psychiatrie culturelle ou sociale sans bras thérapeutique ni résultat applicable
→ Cohortes rétrospectives mono-centriques de petite taille (< 50 patients) \
  sur des molécules sans dossier d'AMM actif
→ Psychologie positive, interventions de bien-être, méditation (hors résultats \
  dans une population psychiatrique constituée en RCT)
→ Neurologie pure : épilepsie, Parkinson, démences (relayer neurologie ou gériatrie)

TERMINOLOGIE — employer sans guillemets ni définition :
EDC (Épisode Dépressif Caractérisé), dépression résistante (≥ 2 lignes adéquates), \
HDRS-17 (Hamilton Depression Rating Scale — score ≥ 17 = dépression modérée-sévère), \
MADRS (Montgomery–Åsberg Depression Rating Scale), PHQ-9 (dépistage), \
IMB (inhibiteur de la monoamine oxydase — IMAO), IRS (inhibiteur recapture sérotonine), \
IRSNA (double — sérotonine + noradrénaline), NaSSA (mirtazapine), \
eskétamine (Spravato — antagoniste NMDA intranasal), zuranolone (agoniste GABAAR), \
potentialisation (lithium / aripiprazole / quétiapine XR / rispéridone), \
ECT (électroconvulsivothérapie — crises tonico-cloniques guidées EEG), \
rTMS (stimulation magnétique transcrânienne répétée — protocoles TBS/HF), \
psilocybine (agoniste 5-HT2A — phases 2/3 en cours), \
TB (Trouble Bipolaire) type I / II, \
lithiémie cible (0,6–0,8 mmol/L prophylaxie ; 0,8–1,0 mmol/L épisode aigu), \
LAI (Long-Acting Injectable antipsychotique — formes LP IM), \
clozapine (schizophrénie ultra-résistante — critères TRTD, surveillance NFS), \
NFS (numération formule sanguine — surveillance agranulocytose clozapine), \
CHR/UHR (Clinical High Risk / Ultra High Risk de psychose), \
PANSS (Positive and Negative Syndrome Scale — schizophrénie), \
TDAH (Trouble Déficit de l'Attention / Hyperactivité), \
MPH (méthylphénidate), LDX (lisdexamfétamine), ATX (atomoxétine), \
SUD (Substance Use Disorder), TSO (Traitement de Substitution aux Opioïdes), \
BHD (buprénorphine haut dosage), \
HO/HDT/SDRE (hospitalisation sous contrainte — soins sans consentement FR), \
TCC (Thérapie Cognitivo-Comportementale — grade A), EMDR (Eye Movement \
  Desensitization and Reprocessing — PTSD, recommandation HAS), \
PTSD (Trouble de Stress Post-Traumatique), \
TAG (Trouble Anxieux Généralisé), \
BED (Binge Eating Disorder), \
STOPP/START (critères iatrogénie gériatrique — interactions psychotropes).

EXEMPLES DE RÉDACTION (style JAMA Psychiatry / Lancet Psychiatry / Am J Psychiatry) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai pivot — nouvelle molécule (résultat centré, pas de méthode en tête) :
  titre_court : "Zuranolone vs placebo : rémission EDC à 15 jours (LANDSCAPE/SHORELINE)"
  resume : "Dans deux RCT de phase 3 (LANDSCAPE, N=543 ; SHORELINE, N=542 — EDC \
modéré-sévère, HDRS-17 ≥ 24), zuranolone 50 mg/j (14 jours) réduit le score HDRS-17 \
de −12,5 pts vs −8,8 pts (placebo) à J15 — différence −3,7 pts (IC95% −5,0 à −2,4 ; \
p<0,001). Taux de rémission (HDRS-17 ≤ 7) : 28,4 % vs 15,8 % à J15. \
Effet sédatif transitoire grade 1-2 : 14,5 % vs 4,2 %. Pas d'excès de pensées \
suicidaires (C-SSRS)."
  impact_pratique : "En pratique : zuranolone offre un délai d'action de 15 jours \
contre 4-6 semaines pour les IRS/IRSNA — à positionner dans l'EDC sévère nécessitant \
une réponse rapide, en alternative à l'eskétamine IV et à l'hospitalisation sous ECT."

Guideline update :
  titre_court : "CANMAT 2023 trouble bipolaire : lurasidone et cariprazine en 1re ligne \
phase dépressive"
  resume : "CANMAT/ISBD Guidelines 2023 (Bipolar Disord suppl.) : révision des \
recommandations pour la phase dépressive du trouble bipolaire type I et II. \
Lurasidone (20–120 mg/j) et cariprazine (1,5–3 mg/j) obtiennent désormais un niveau \
d'évidence 1 (multiple RCTs) pour le TB-I et TB-II, à égalité avec la quetiapine XR. \
Lithium et lamotrigine conservent leur grade 1 en prévention des récurrences \
dépressives TB-II. L'olanzapine-fluoxétine reste 2e ligne (profil métabolique)."
  impact_pratique : "À retenir : lurasidone est à privilégier en 1re intention \
pour la dépression bipolaire type II — efficacité démontrée sans le risque \
métabolique de la quetiapine XR ou de l'olanzapine."

Alerte réglementaire :
  titre_court : "ANSM : valproate contre-indiqué chez la femme en âge de procréer \
sans contraception efficace — rappel de mesures 2024"
  resume : "ANSM (DHPC, jan. 2026) : rappel des mesures de minimisation du risque \
valproate — tératogénicité (risque malformations : 10 % ; troubles \
neurodéveloppementaux : 30–40 %). Obligation légale : formulaire d'accord de soins \
signé annuellement, contraception efficace documentée, consultation spécialisée \
avant toute prescription ou renouvellement chez une femme de 15 à 50 ans. \
En psychiatrie : indication résiduelle uniquement en trouble bipolaire de type I \
résistant, après échec lithium + 2 autres thymorégulateurs."
  impact_pratique : "En pratique : vérifier à chaque renouvellement la présence du \
formulaire signé et d'une contraception documentée — l'absence de l'un ou l'autre \
rend la prescription non conforme aux exigences ANSM, avec responsabilité engagée."
"""

_SPECIALTY_ADDENDUM_PNEUMOLOGIE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — PNEUMOLOGIE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : pneumologue (CHU / clinique / cabinet, France / Europe), \
maîtrisant explorations fonctionnelles respiratoires (EFR, pléthysmographie, \
DLCO, test de marche 6 min), bronchoscopie diagnostique et interventionnelle, \
CPAP/VNI, endoscopie bronchique (cryobiopsie, EBUS), pneumologie oncologique \
(immunothérapie en 1re ligne, TKI, décision RCP). \
Référentiels actuels : ERS/ATS COPD Guidelines (GOLD 2025), GINA 2024 (asthme), \
ERS/ESC Guidelines HTAP 2022, ATS/ERS guidelines FPI/ILD 2022, \
recommandations SPLF (BPCO, apnée du sommeil, tabacologie), HAS guides BPCO/asthme. \
Essais pivots de référence : IMPACT trial (ICS/LABA/LAMA triplet BPCO), \
GALATHEA/TERRANOVA (benralizumab BPCO), NAVIGATOR (tézépélumab asthme sévère), \
LIBERTY ASTHMA QUEST (dupilumab asthme modéré-sévère), INPULSIS (nintédanib FPI), \
CAPACITY/ASCEND (pirfénidone FPI), AMBITION (macitentan+tadalafil HTAP), \
STELLAR (sotatercept HTAP), GRIPHON (sélexipag HTAP), \
KEYNOTE-189 (pembrolizumab+chimio NSCLC non-squameux 1re ligne), \
essais pivots Kaftrio phase 3 (elexacaftor-tezacaftor-ivacaftor, NEJM 2019 — Heijerman, Middleton).

CRITÈRE DE PERTINENCE PNEUMOLOGIQUE :
"Ce résultat va-t-il modifier une stratégie thérapeutique, le choix d'un inhalateur, \
l'indication d'une biothérapie, ou le suivi d'un patient dans ma consultation dans \
les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : BPCO/asthme léger sans impact sur step-up/down, \
pathologie ultra-rare sans dispositif thérapeutique accessible en France, \
résultats confirmatoires d'une stratégie déjà intégrée aux guidelines ERS/ATS/GINA/GOLD, \
essai purement physiologique (mécanique ventilatoire) sans traduction clinique, \
études animalières pulmonaires sans essai clinique associé.

FILTRES SPÉCIFIQUES :

RETENIR :
→ BPCO : nouvelles classes thérapeutiques, triplet ICS/LABA/LAMA, exacerbations \
  aiguës (antibiothérapie, corticothérapie systémique, VNI), phénotypes (ACOS, \
  emphysème, bronchiteux chronique), réhabilitation respiratoire, spirométrie post-\
  COVID, cystoprofilaxie, azithromycine de maintenance
→ Asthme : biothérapies en asthme sévère (anti-IL5 : mepolizumab/reslizumab/\
  benralizumab ; anti-IL4/IL13 : dupilumab ; anti-TSLP : tézépélumab ; \
  anti-IgE : omalizumab), step-up/down GINA, biologie à l'initiative du pharmacien \
  en observance inhalateur, phénotypage T2/non-T2, FeNO
→ ILD (Interstitial Lung Disease) / FPI : nouveaux antifibrotiques, cryobiopsie \
  trans-bronchique (résultats diagnostiques vs CBT chirurgicale), télémédecine suivi \
  CVF, FPI + emphysème (CPFE), HP (pneumonie d'hypersensibilité) — critères diagnostiques
→ Hypertension pulmonaire artérielle (HTAP) : nouvelles associations (sotatercept, \
  sélexipag), stratification risque (COMPERA), critères de référence au CHU
→ Infections respiratoires : PAC (SPBC/S. pneumoniae, Legionella, atypiques — \
  antibiothérapie guidée PCT), pneumonies à COVID-19 résiduelles, \
  PAVM/PNAVM en réanimation (co-morbidité pneumologue), tuberculose résistante (RR-TB), \
  NTM pulmonaire (Mycobacterium avium complex — critères ATS/ERS)
→ Cancer broncho-pulmonaire : côté médical (pas chirurgie) — immunothérapie 1re/2e ligne \
  (anti-PD1/PDL1), TKI (EGFR/ALK/RET/ROS1/KRAS), SCLC (atézolizumab maintenance), \
  VT-PET-scan, biomarqueurs (PD-L1, TMB, NGS panel tumoral), \
  effets pulmonaires des ICI (pneumopathie interstitielle immune grade 2-4)
→ Mucoviscidose (CF) : modulateurs CFTR (elexacaftor-tezacaftor-ivacaftor / Kaftrio), \
  nouvelles combinaisons, données de vie réelle France, infections à Pseudomonas
→ Apnée du sommeil (SAOS) : CPAP vs orthèse d'avancée mandibulaire, nouvelles \
  thérapies (stimulation du nerf hypoglosse — Inspire Medical Systems, Genio), \
  impact cardiovasculaire (SAVE trial, ISAACC trial), SAOS sévère et \
  évènements coronariens, suivi observance CPAP (données télémonitoring)
→ Tabacologie : nouvelles pharmacothérapies (varénicline, cytisine, combinaisons), \
  cigarette électronique (données LT) — si impact sur pratique de sevrage
→ Alertes ANSM/EMA : retraits d'inhalateurs, nouvelles CI bronchodilatateurs, \
  pneumopathies médicamenteuses (amiodarone, MTX, nitrofurantoïne, bléomycine)

REJETER :
→ BPCO/asthme léger (GOLD A/B ou GINA step 1-2) sans résultat modifiant la pratique
→ Études purement physiologiques (courbes débit-volume, compliance dynamique) \
  sans application clinique testée
→ Infections respiratoires virales bénignes (rhinopharyngite, bronchite aiguë) \
  sans résultat sur antibiothérapie ou antiviral
→ Cancérologie : phase 1 d'escalade de dose (relayer oncologie)
→ Études animalières pulmonaires (modèles souris BPCO, asthme) sans essai clinique
→ Pollution atmosphérique / épidémiologie environnementale seule, sans résultat \
  clinique applicable en consultation

TERMINOLOGIE — employer sans guillemets ni définition :
BPCO (Broncho-Pneumopathie Chronique Obstructive), GOLD A/B/C/D, VEMS (FEV₁), \
CVF (FVC), ratio VEMS/CVF (Tiffeneau), DLCO (diffusion CO), \
bronchodilatateur à courte durée d'action (BDCA : SABA + SAMA), \
bronchodilatateur à longue durée d'action (BDLA : LABA + LAMA), \
ICS (Inhaled Corticosteroids), triplet ICS/LABA/LAMA, \
ACOS (Asthma-COPD Overlap Syndrome), \
exacerbation aiguë de BPCO (EABPCO), \
GINA step 1-5, FeNO (Fractional exhaled Nitric Oxide — seuil > 25 ppb T2), \
IgE totales / spécifiques (RAST), tests de provocation bronchique (métacholine), \
FPI (Fibrose Pulmonaire Idiopathique), CVF % prédit, \
nintédanib / pirfénidone (antifibrotiques), \
HTAP (Hypertension Pulmonaire Artérielle), PAPm (pression artérielle pulmonaire \
  moyenne — seuil AMM ≥ 20 mmHg), RVP (résistances vasculaires pulmonaires), \
  COMPERA (score risque HTAP), ERA (antagoniste des récepteurs à l'endothéline), \
  PDE5i (inhibiteur PDE-5 : sildénafil / tadalafil), sGC (riociguat), \
  sotatercept (activine / BMPR2), sélexipag (agoniste IP), \
PAC (Pneumonie Acquise en Communauté), PAVM (Pneumonie Acquise sous Ventilation \
  Mécanique), PCT (procalcitonine), CRP, antigénuries Legionella/pneumocoque, \
VNI (Ventilation Non Invasive), CPAP (Continuous Positive Airway Pressure), \
SAOS (Syndrome d'Apnée Obstructive du Sommeil), IAH (index apnée-hypopnée — \
  léger 5-15, modéré 15-30, sévère > 30 /h), SpO₂, désaturation nocturne, \
OAM (Orthèse d'Avancée Mandibulaire), stimulation hypoglosse (Inspire), \
CF (Cystic Fibrosis — mucoviscidose), CFTR (Cystic Fibrosis Transmembrane Conductance \
  Regulator), modulateur CFTR (elexacaftor-tezacaftor-ivacaftor / Kaftrio), \
EFR (Explorations Fonctionnelles Respiratoires), TVO (trouble ventilatoire \
  obstructif), TVR (trouble ventilatoire restrictif), \
EBUS (Endobronchial Ultrasound), \
TM6M (test de marche de 6 minutes — distance, désaturation), SpO₂ effort.

EXEMPLES DE RÉDACTION (style ERJ / AJRCCM / Lancet Respir Med) :
Règle resume (style journal spécialisé) : Phrase 1 = énonce le résultat clinique en langage naturel, le chiffre clé (réduction relative, HR/RR/OR + IC95% + p) intégré en incise — pas en tête de phrase. Ex : 'Le rivaroxaban réduit de 24 % le risque d'événement CV majeur dans l'AOMI (HR 0,76 ; IC95% 0,66–0,86 ; p<0,001).' Phrase 2 = design en 1 ligne (acronyme si connu, type étude, N, population, durée). Ne jamais ouvrir par l'acronyme, la méthode ou le type d'étude.\


Essai pivot (biothérapie asthme) :
  titre_court : "Tézépélumab asthme sévère non-T2 : NAVIGATOR 52 semaines"
  resume : "NAVIGATOR (RCT, N=1 061, asthme sévère non contrôlé toutes phénotypes, \
suivi 52 semaines) : tézépélumab (anti-TSLP) réduit le taux annualisé d'exacerbations \
de 70 % vs placebo (0,93 vs 3,10 — IRR 0,30 ; IC95% 0,24–0,37 ; p<0,001) quel que \
soit le phénotype T2 ou non-T2. VEMS +0,13 L vs +0,08 L. FeNO, IgE, éosinophiles \
améliorés uniformément. Sous-groupe non-T2 (FeNO < 25, éosinophiles < 150) : réduction \
exacerbations 70 %, IRR 0,30 (IC95% 0,17–0,53)."
  impact_pratique : "En pratique : tézépélumab est le seul anti-TSLP efficace dans les \
phénotypes non-T2 — à proposer en 1re intention pour les asthmatiques sévères non \
contrôlés sans argument éosinophile ni allergique."

Guideline update (BPCO) :
  titre_court : "GOLD 2025 : triplet d'emblée si symptômes élevés et > 1 exacerbation"
  resume : "GOLD 2025 (rapport annuel) : mise à jour majeure de la stratification \
initiale — passage au triplet ICS/LABA/LAMA recommandé d'emblée (Grade IA) pour les \
patients GOLD B à D avec ≥ 1 exacerbation modérée/an, quel que soit le niveau d'IgE. \
Basé sur ETHOS (N=8 509) : réduction exacerbations modérées-sévères 24 % vs doublet LABA/LAMA. \
Abandon du schéma 'monothérapie → doublet → triplet' pour ce sous-groupe."
  impact_pratique : "À retenir : classifier les patients BPCO en 'post-bronchodilatateur' \
(VEMS/CVF < 0,70) + ≥ 1 exacerbation → initier le triplet d'emblée sans attendre l'échec \
du doublet."

Alerte sécurité inhalateurs :
  titre_court : "ANSM : suspension Formotérol/Béclométasone (lot XXXX) — contamination"
  resume : "ANSM (lettre professionnels, mars 2026) : rappel de lots d'aérosol doseur \
Formotérol/Béclométasone 6/100 µg (Chiesi — lot XXX-XXX) après détection d'un taux \
de particules fines hors spécification (< 1,5 µm : 41 % au lieu de ≤ 35 %). \
Environ 12 000 boîtes concernées en France. \
Les patients asymptomatiques sous ces lots ne doivent pas interrompre leur traitement."
  impact_pratique : "En pratique : identifier les patients porteurs du lot concerné \
et remplacer à la prochaine dispensation — déclarer tout doute de contrôle insuffisant \
en pharmacovigilance via le portail signalement-sante.gouv.fr."
"""

_SPECIALTY_ADDENDUM_PHARMACIEN = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — PHARMACIEN (OFFICINE ET HOSPITALIER)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : pharmacien d'officine ou pharmacien hospitalier (PH, CHU / CH, France), \
maîtrisant dispensation, pharmacovigilance, conciliation médicamenteuse, \
bon usage, circuit du médicament, interactions, pharmacocinétique clinique, \
stérilisation / préparations magistrales et hospitalières. \
Référentiels actuels : SFPC recommandations, EAHP Good Practice Statements 2022, \
HAS fiches de bon usage médicament, ANSM guides de bon usage, \
Thériaque / Vidal / interactions ANSM, Répertoire des spécialités pharmaceutiques. \
Points d'attention réglementaires : liste des médicaments à risque (LASA, forte \
vigilance), décret de compétences officinales (vaccination, TROD, bilan de médication), \
Circuit ATU/AAP ANSM-HAS, biosimilaires interchangeables (liste ANSM).

CRITÈRE DE PERTINENCE PHARMACIEN :
"Ce résultat va-t-il modifier un acte de dispensation, une décision de substitution, \
un protocole de bon usage, ou la détection d'une interaction/toxicité en pratique \
quotidienne française dans les 1-3 ans ?" \
Rejeter même une étude robuste si : recherche fondamentale en pharmacologie sans \
application clinique immédiate, PK/PD uniquement chez la souris, essai de phase 1 \
sans données d'efficacité/tolérance en routine, pathologie ultra-rare sans impact \
sur les médicaments dispensés en ville ou à l'hôpital en France.

FILTRES SPÉCIFIQUES :

RETENIR :
→ Nouvelles interactions médicamenteuses cliniquement significatives (grade contre-\
  indication ou précaution majeure ANSM/ANSM) : mécanisme CYP, transporteurs P-gp/BCRP, \
  allongement QTc, hyperkaliémie, néphrotoxicité cumulée
→ Alertes pharmacovigilance / matériovigilance ANSM : nouveaux signaux de sécurité, \
  lettres aux professionnels de santé (DHPC — Direct Healthcare Professional Communication), \
  retraits de lots, suspensions AMM, modifications de RCP
→ Ruptures d'approvisionnement et tensions d'approvisionnement : médicaments à liste \
  ANSM, alternatives thérapeutiques validées HAS, protocoles de gestion
→ Biosimilaires : nouvelles inscriptions sur la liste ANSM, données d'interchangeabilité \
  et d'immunogénicité, résultats de pharmaco-épidémiologie post-commercialisation
→ Bon usage hospitalier : protocoles de conciliation médicamenteuse (iatrogénie évitée), \
  sécurisation circuit chimiothérapie (préparation centralisée, double vérification), \
  préparations magistrales ANSM, stérilisation ISO — uniquement si changement de pratique
→ Décret de compétences officinales : nouvelles missions (vaccination 2025, TROD, \
  bilan de médication SFD/CNGE, dispensation d'urgence contraception), impact sur \
  prescription déléguée et traçabilité
→ Pharmacocinétique clinique impactant le suivi thérapeutique : TDM (Therapeutic \
  Drug Monitoring) nouvelles molécules ou nouvelles cibles — aminosides, vancomycine \
  (AUC-guided), imipenem/méropénem/pipéracilline TDM, antiépileptiques, anti-TNF
→ Transition hospitalier-ville : coordination sorties d'hospitalisation, ordonnances \
  de sortie (réforme 2025), bilan partagé de médication (BPM ASIP/HAS)
→ Réglementation stupéfiants / psychotropes : modifications quotas, nouvelles \
  inscriptions / déclassements, règles de prescription sécurisée
→ Pharmaco-épidémiologie : études en vie réelle (bases SNDS/EGB) sur l'utilisation \
  réelle des médicaments, effets indésirables en population, mésusage

REJETER :
→ Recherche fondamentale (cible moléculaire, modèle animal) sans résultats cliniques \
  disponibles ou attendus à court terme
→ Essais de phase 1 d'escalade de dose (aucun impact sur dispensation actuelle)
→ Articles de pharmacologie académique pure (interactions CYP in vitro non confirmées \
  cliniquement)
→ Études sur systèmes de santé étrangers non transposables en France (Medicaid, NHS \
  formularies sans équivalent ANSM)
→ Économie de santé / coût-efficacité sans recommandation HAS ou décision de prise \
  en charge associée
→ Soins infirmiers et protocoles paramédicaux (relayer vers infirmiers si pertinent)

TERMINOLOGIE — employer sans guillemets ni définition :
AMM (Autorisation de Mise sur le Marché), RCP (Résumé des Caractéristiques du Produit), \
DCI (Dénomination Commune Internationale), ANSM, HAS, ATU / AAP (Accès Précoce), \
DHPC (lettre aux professionnels de santé), MTE (médicament à tolérance étroite), \
LASA (Look-Alike Sound-Alike — médicaments à risque de confusion), \
TDM (Therapeutic Drug Monitoring — suivi thérapeutique pharmacologique), \
AUC (Aire sous la courbe — AUC24/MIC pour vancomycine), \
Css (concentration à l'équilibre), Cmin / Cmax, demi-vie t½, biodisponibilité F, \
CYP3A4/3A5 (inducteurs : rifampicine, carbamazépine / inhibiteurs : azolés, macrolides), \
P-gp / BCRP (transporteurs d'efflux), \
biosimilaire / médicament biologique de référence, \
interchangeabilité (liste ANSM biosimilaires), immunogénicité, anticorps anti-médicament, \
conciliation médicamenteuse (CM entrée / sortie), bilan partagé de médication (BPM), \
iatrogénie médicamenteuse, EI (effet indésirable), pharmacovigilance, \
préparation hospitalière (PH) / préparation magistrale (PM) / MITM, \
chimiothérapie anticancéreuse en UPC (Unité de Préparation des Cytotoxiques), \
RTU (Recommandation Temporaire d'Utilisation — remplacée par l'AAP), \
substitution générique / biosimilaire à l'officine, ordonnance sécurisée (stupéfiants), \
SMR / ASMR (évaluation HAS — Service Médical Rendu / Amélioration), IQSS.

EXEMPLES DE RÉDACTION (style Ann Pharm Fr / Eur J Hosp Pharm / SFPC) :

Alerte ANSM — interaction médicamenteuse :
  titre_court : "ANSM : association méropénem–valproate — contre-indication renforcée"
  resume : "DHPC ANSM (fév. 2026) : mise à jour du RCP méropénem et valproate de sodium \
suite à 18 cas de perte de contrôle épileptique documentés en pharmacovigilance européenne. \
Mécanisme : inhibition de l'hydrolyse du valproate-glucuronide par les β-lactamines \
(réduction plasma jusqu'à 80 %). Délai d'action rapide (< 48 h). Contre-indication \
formelle maintenue — aucune alternative β-lactamine validée (imipenem, pipéracilline \
même effet)."
  impact_pratique : "En pratique : signaler systématiquement cette CI à l'équipe \
médicale à chaque nouvelle prescription de méropénem chez un patient sous valproate ; \
monitorer la valproatémie en cas d'antécédent récent."

Biosimilaire — nouvelle inscription liste ANSM :
  titre_court : "Adalimumab biosimilaire : 3 nouvelles spécialités interchangeables (ANSM 2026)"
  resume : "ANSM (liste biosimilaires, actualisation mars 2026) : Hyrimoz, Idacio et \
Simlandi ajoutés à la liste d'interchangeabilité avec Humira pour les indications \
rhumatologiques et dermatologiques. Données de pharmacovigilance : 2 ans de suivi \
post-commercialisation en Europe — incidence anticorps anti-médicament comparable à \
la molécule de référence (5,1 % vs 5,4 %, différence non significative, EBPG 2025)."
  impact_pratique : "En pratique : la substitution par le pharmacien hospitalier \
est possible sans réévaluation médicale — documenter la substitution dans le dossier \
patient et informer le prescripteur conformément à l'arrêté du 20 juillet 2024."

Conciliation médicamenteuse — résultat de pratique :
  titre_court : "Conciliation entrée : réduction 48 % iatrogénie à l'hôpital (étude CORIS)"
  resume : "CORIS (étude prospective multicentrique française, 12 services médecine interne, \
N=1 240) : conciliation médicamenteuse systématique à l'entrée — 48 % de réduction des \
événements iatrogènes médicamenteux évitables (4,2 vs 8,1/100 admissions ; p<0,001). \
Médicaments les plus impliqués : anticoagulants (23 %), antihypertenseurs (18 %), \
antidiabétiques oraux (14 %). Temps moyen de conciliation : 22 minutes par patient."
  impact_pratique : "À retenir : la conciliation à l'entrée réduit de moitié l'iatrogénie \
évitable — argument pour formaliser le protocole dans tout établissement sans conciliation \
systématisée (cible IPAQSS 2026)."
"""

_SPECIALTY_ADDENDA: dict[str, str] = {
    "anesthesiologie":        _SPECIALTY_ADDENDUM_ANESTHESIOLOGIE,
    "biologiste":             _SPECIALTY_ADDENDUM_BIOLOGISTE,
    "cardiologie":            _SPECIALTY_ADDENDUM_CARDIOLOGIE,
    "chirurgie-orthopedique": _SPECIALTY_ADDENDUM_ORTHOPEDIE,
    "chirurgie-thoracique":   _SPECIALTY_ADDENDUM_THORACIQUE,
    "chirurgie-vasculaire":   _SPECIALTY_ADDENDUM_VASCULAIRE,
    "chirurgie-cardiaque":    _SPECIALTY_ADDENDUM_CARDIAQUE,
    "chirurgie-plastique":    _SPECIALTY_ADDENDUM_PLASTIQUE,
    "chirurgie-pediatrique":  _SPECIALTY_ADDENDUM_PEDIATRIQUE,
    "dermatologie":           _SPECIALTY_ADDENDUM_DERMATOLOGIE,
    "endocrinologie":         _SPECIALTY_ADDENDUM_ENDOCRINOLOGIE,
    "gastro-enterologie":     _SPECIALTY_ADDENDUM_GASTROENTEROLOGIE,
    "geriatrie":              _SPECIALTY_ADDENDUM_GERIATRIE,
    "gynecologie":            _SPECIALTY_ADDENDUM_GYNECOLOGIE,
    "hematologie":            _SPECIALTY_ADDENDUM_HEMATOLOGIE,
    "infectiologie":          _SPECIALTY_ADDENDUM_INFECTIOLOGIE,
    "infirmiers":             _SPECIALTY_ADDENDUM_INFIRMIERS,
    "kinesitherapie":         _SPECIALTY_ADDENDUM_KINESITHERAPIE,
    "medecine-generale":      _SPECIALTY_ADDENDUM_MEDECINE_GENERALE,
    "medecine-interne":       _SPECIALTY_ADDENDUM_MEDECINE_INTERNE,
    "medecine-physique":      _SPECIALTY_ADDENDUM_MPR,
    "medecine-urgences":      _SPECIALTY_ADDENDUM_URGENCES,
    "nephrologie":            _SPECIALTY_ADDENDUM_NEPHROLOGIE,
    "neurochirurgie":         _SPECIALTY_ADDENDUM_NEUROCHIRURGIE,
    "neurologie":             _SPECIALTY_ADDENDUM_NEUROLOGIE,
    "oncologie":              _SPECIALTY_ADDENDUM_ONCOLOGIE,
    "ophtalmologie":          _SPECIALTY_ADDENDUM_OPHTALMOLOGIE,
    "orl":                    _SPECIALTY_ADDENDUM_ORL,
    "pediatrie":              _SPECIALTY_ADDENDUM_PEDIATRIE,
    "pharmacien":             _SPECIALTY_ADDENDUM_PHARMACIEN,
    "pneumologie":            _SPECIALTY_ADDENDUM_PNEUMOLOGIE,
    "psychiatrie":            _SPECIALTY_ADDENDUM_PSYCHIATRIE,
    "radiologie":             _SPECIALTY_ADDENDUM_RADIOLOGIE,
    "rhumatologie":           _SPECIALTY_ADDENDUM_RHUMATOLOGIE,
    "sage-femme":             _SPECIALTY_ADDENDUM_SAGE_FEMME,
    "urologie":               _SPECIALTY_ADDENDUM_UROLOGIE,
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
        specialty_hint=specialty_hint,
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
    "legifrance_jorf_remboursement": {
        # Mots-clés titre déjà filtrés côté PISTE → pas de whitelist locale.
        # Seuil LLM relevé à 6 : un arrêté de remboursement doit apporter un
        # changement actionnable (nouveau prix, nouvelle inscription/radiation)
        # pour figurer dans la newsletter.
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
    # ── HAS — Accès précoce (ex-ATU) ─────────────────────────────────────
    # Faible volume, haute valeur : décision nominative par médicament → seuil bas
    "has_acces_precoces": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    # ── HAS — Bulletin officiel ──────────────────────────────────────────
    # Décisions formelles numérotées (accès précoce, avis vaccin, CEESP)
    "has_bo": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ── ANSM — Points d'information ──────────────────────────────────────
    # Communiqués variés (pharmacovigilance, bilans, signaux émergents)
    "ansm_actualites": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    # ── INCa — Recommandations nationales oncologie ───────────────────────
    # Référentiels officiels → contenu toujours pertinent pour oncologie
    "inca_recommandations": {
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
    # Source exclusivement médicale : toutes les publications sont soit
    # pertinentes (exercice libéral, déontologie, honoraires) soit
    # rejetées par le LLM. Pas besoin de whitelist JORF — les titres CNOM
    # utilisent un vocabulaire institutionnel ("PDSA", "certification",
    # "Ordre") absent de la whitelist sanitaire.
    # CGU CNOM autorisent RSS avec attribution ✅
    "cnom": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ── ameli.fr/medecin — convention médicale, honoraires, CNAM ─────────────
    # Source mixte : convention médicale / tarifs (reglementaire) ET outils
    # praticiens (recommandation) → source_type déterminé par LLM.
    # Pas de whitelist : contenu 100% médecins libéraux, pas de bruit.
    "ameli_medecin": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ── CARMF — retraite et cotisations médecins libéraux ────────────────
    # Source exclusivement médicale, ~3-5 articles/an.
    # Contenu : PSS, taux cotisations CARMF, ASV, prévoyance médecins.
    "carmf": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ── CARPIMKO — retraite auxiliaires médicaux libéraux ─────────────────
    # Source exclusivement para-médicale, ~6-12 articles/an.
    # Contenu : cotisations, réforme assiette sociale, cumul emploi-retraite.
    "carpimko": {
        "require_whitelist": False,
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
    # ema_guidelines : guidelines CHMP/ICH — faible volume, haute valeur → seuil 5
    "ema_guidelines": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ecdc_risk / ecdc_guidance / ecdc_cdtr : infectiologie uniquement → seuil 5
    "ecdc_risk": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "ecdc_guidance": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "ecdc_cdtr": {
        "require_whitelist": False,
        "min_llm_score": 5,
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
# Pré-filtre par spécialité (inclusion keywords — sources "tous" uniquement)
# ---------------------------------------------------------------------------
# Logique : pour les sources specialty_hint=="tous" (HAS, ANSM, EMA, JAMA, NEJM…),
# le titre doit contenir AU MOINS UN terme de la spécialité cible pour passer.
# Les sources spé-spécifiques (hint == slug) ignorent ce filtre.
# Termes FR + EN pour couvrir les journaux anglophones et les sources françaises.

SPECIALTY_PREFILTER_KEYWORDS: dict[str, list[str]] = {
    "anesthesiologie": [
        r"(?i)\banesthési", r"(?i)\banalgési", r"(?i)\bsédation\b",
        r"(?i)\bopioïd", r"(?i)\bmorphine\b", r"(?i)\bsufentanil\b",
        r"(?i)\brémifentanil\b", r"(?i)\bfentanyl\b", r"(?i)\bkétamine\b",
        r"(?i)\bpropofol\b", r"(?i)\bintubation\b", r"(?i)\blocorégional",
        r"(?i)\bALR\b", r"(?i)\bbloc\s+nerveux\b", r"(?i)\bépidurale\b",
        r"(?i)\brachisthésie\b", r"(?i)\bdouleur\s+post.?op", r"(?i)\bRAAC\b",
        r"(?i)regional anesthes", r"(?i)\bneuraxial\b", r"(?i)sedation\b",
        r"(?i)analges", r"(?i)pain management", r"(?i)\bairway\b",
        r"(?i)perioperative", r"(?i)postoperative pain", r"(?i)\bcurare\b",
        r"(?i)\brocuronium\b", r"(?i)enhanced recovery", r"(?i)\bERAS\b",
        r"(?i)\bdouleur chronique\b", r"(?i)\bneuromuscular block",
    ],
    "biologiste": [
        r"(?i)\bbiologie\b", r"(?i)\bbiomarqueur", r"(?i)\bhémogramme\b",
        r"(?i)\bsérologie\b", r"(?i)\bbactériologi", r"(?i)\bmicrobiologi",
        r"(?i)\bdiagnostic\s+(biologique|moléculaire|in\s+vitro)",
        r"(?i)\bPCR\b", r"(?i)\bELISA\b", r"(?i)\bdosage\b",
        r"(?i)\bgénomiq", r"(?i)\bséquençage\b", r"(?i)\bNGS\b",
        r"(?i)\blaboratoire\s+d[e']analyse", r"(?i)\bDM.DIV\b",
        r"(?i)\bbiobank", r"(?i)\bprotéomiq", r"(?i)\bimmunohistochimi",
        r"(?i)\bcytologi", r"(?i)biomarker", r"(?i)laboratory test",
        r"(?i)point.of.care test", r"(?i)\bDNA\b", r"(?i)\bRNA\b",
        r"(?i)\bannexe\s+biologique\b",
    ],
    "cardiologie": [
        r"(?i)\bcardiaqu", r"(?i)\bcoronar", r"(?i)\binfarctu",
        r"(?i)insuffisance cardiaque", r"(?i)\barythmie\b",
        r"(?i)fibrillation\s+(auriculaire|ventriculaire)",
        r"(?i)\btachycardie\b", r"(?i)\bbradycardie\b",
        r"(?i)\bhypertension\b", r"(?i)\bantihypertenseur",
        r"(?i)\bbêtabloquant\b", r"(?i)\biECA\b", r"(?i)\bsartan\b",
        r"(?i)\bstatine\b", r"(?i)\banticoagulant", r"(?i)\bAOD\b",
        r"(?i)\bTAVI\b", r"(?i)\bpontage\b", r"(?i)\bstents?\b",
        r"(?i)\bangioplastie\b", r"(?i)\béchocardiograph",
        r"(?i)\bpacemaker\b", r"(?i)\bdéfibrillateur\b", r"(?i)\bDAI\b",
        r"(?i)\baortique\b", r"(?i)\bmitrale\b", r"(?i)\btricuspide\b",
        r"(?i)\bIDM\b", r"(?i)\bSCA\b", r"(?i)\bheart failure\b",
        r"(?i)\batrial fibrillation\b", r"(?i)\bmyocardial infarct",
        r"(?i)\bhypertens", r"(?i)\bcardiovascular\b", r"(?i)\bcoronary\b",
        r"(?i)\bantiplatelet\b", r"(?i)\bGLP.1\b", r"(?i)\bsemaglutide\b",
        r"(?i)\bempagliflozin\b", r"(?i)\bSGLT.?2\b",
    ],
    "chirurgie-cardiaque": [
        r"(?i)chirurgie\s+(cardiaque|cardiac)", r"(?i)\bCABG\b",
        r"(?i)pontage\s+coronar", r"(?i)\bvalv(e|ulaire|uloplastie)",
        r"(?i)remplacement\s+valvulaire", r"(?i)\baorte\s+ascendante\b",
        r"(?i)transplantation\s+(cardiaque|cardiac)", r"(?i)\bLVAD\b",
        r"(?i)\bECMO\b", r"(?i)assistance\s+circulatoire",
        r"(?i)mechanical\s+(circulatory|heart)\s+support",
        r"(?i)cardiac surgery", r"(?i)\bEACTS\b",
        r"(?i)\bthoracotomie\b", r"(?i)\bcirculat\b.*\bextracorporelle\b",
        r"(?i)cardioplegia", r"(?i)valve\s+(repair|replacement)",
    ],
    "chirurgie-orthopedique": [
        r"(?i)\bos\b", r"(?i)\bfracture\b", r"(?i)\barthropl(astie|asty)",
        r"(?i)\bprothèse\s+(hanche|genou|épaule)", r"(?i)\bhanche\b",
        r"(?i)\bgenou\b", r"(?i)\brachis\b", r"(?i)\bvertèbre\b",
        r"(?i)\bscoliose\b", r"(?i)\barthroscopie\b", r"(?i)\bligament\b",
        r"(?i)\btendon\b", r"(?i)\bostéotomie\b", r"(?i)\bostéoporose\b",
        r"(?i)\bostéosynthèse\b", r"(?i)\btotal hip\b", r"(?i)\btotal knee\b",
        r"(?i)\bspine\b", r"(?i)\bfracture\b", r"(?i)\bbone\b",
        r"(?i)\borthopedi", r"(?i)\bimplant\s+orthopéd",
        r"(?i)\blumbar\b", r"(?i)\bcervical\b", r"(?i)\bdiscal\b",
    ],
    "chirurgie-pediatrique": [
        r"(?i)chirurgie\s+pédiatr", r"(?i)\bhernie\s+(inguinale|ombilicale)",
        r"(?i)\bappendicit\b", r"(?i)\binvagination\b",
        r"(?i)\bmalformation\s+(congénital|digestive)",
        r"(?i)\blaparotomie\s+enfant\b", r"(?i)\bnéonatale?\b",
        r"(?i)\bpédiatr", r"(?i)\benfant\b", r"(?i)\bnourrisson\b",
        r"(?i)\bpediatric surgery\b", r"(?i)\bneonatal surgery\b",
        r"(?i)\batrésie\b", r"(?i)\bocclusion\s+néonatal",
        r"(?i)\bhydrocèle\b", r"(?i)\bcryptorchidie\b",
    ],
    "chirurgie-plastique": [
        r"(?i)\breconstruct", r"(?i)\bgreffe\s+(de\s+peau|cutanée)",
        r"(?i)\blambeau\b", r"(?i)\brhinoplast", r"(?i)\bmammoplast",
        r"(?i)\bliposuccion\b", r"(?i)\bbrûlure\b", r"(?i)\bcicatrice\b",
        r"(?i)\bkéloïde\b", r"(?i)chirurgie\s+(réparatrice|esthétique|plastique)",
        r"(?i)\bmastectomie\b", r"(?i)\breconstruction\s+mammaire\b",
        r"(?i)\bplastic surgery\b", r"(?i)\breconstruction\b",
        r"(?i)\bskin graft\b", r"(?i)\bflap\b", r"(?i)\bbody contouring\b",
    ],
    "chirurgie-thoracique": [
        r"(?i)\bthoraci", r"(?i)\bpoumon\b", r"(?i)\bplèvre\b",
        r"(?i)\bmédiast", r"(?i)\btrachée\b", r"(?i)\bœsophage\b",
        r"(?i)\blobectomie\b", r"(?i)\bpneumonectomie\b",
        r"(?i)\bthoracoscopie\b", r"(?i)\bVATS\b",
        r"(?i)\brésection\s+pulmonaire\b", r"(?i)lung\s+(resection|cancer)",
        r"(?i)thoracic surgery", r"(?i)\besophageal\b", r"(?i)\bpneumothorax\b",
        r"(?i)\bépanchement\s+pleural\b", r"(?i)\bempyème\b",
    ],
    "chirurgie-vasculaire": [
        r"(?i)\baorte\b", r"(?i)\banévrisme\b", r"(?i)\bartériopathie\b",
        r"(?i)\biscémie\b", r"(?i)\bischémie\b", r"(?i)\brévascularisation\b",
        r"(?i)\bendoprothèse\b", r"(?i)\bEVAR\b", r"(?i)\bTEVAR\b",
        r"(?i)\bvarice\b", r"(?i)\bartère\s+(fémorale|poplitée|iliaque)",
        r"(?i)\bthrombose\s+(veineuse|artérielle)", r"(?i)\bclaudication\b",
        r"(?i)\bamput", r"(?i)\bpied\s+diabétique\b", r"(?i)\bcarotide\b",
        r"(?i)\bendarterect", r"(?i)vascular surgery", r"(?i)\baortic\b",
        r"(?i)\baneurysm\b", r"(?i)peripheral\s+artery", r"(?i)\bbypass\b",
        r"(?i)\bstenting\b", r"(?i)deep vein thrombosis", r"(?i)\bDVT\b",
    ],
    "dentiste": [
        r"(?i)\bdentaire\b", r"(?i)\bdent\b", r"(?i)\bparodont",
        r"(?i)\bcarie\b", r"(?i)\bendodont", r"(?i)\bimplant\s+dentaire\b",
        r"(?i)\bbucco.dentaire\b", r"(?i)\bmuqueuse\s+buccale\b",
        r"(?i)chirurgie\s+orale\b", r"(?i)\bodontologi", r"(?i)\bpulpe\b",
        r"(?i)\bdental\b", r"(?i)\boral\s+(health|hygiene|surgery)",
        r"(?i)\borthodont", r"(?i)\bpériodont", r"(?i)\bxérostomie\b",
        r"(?i)\bbouche\b", r"(?i)\bgencive\b",
    ],
    "dermatologie": [
        r"(?i)\bpeau\b", r"(?i)\bdermite\b", r"(?i)\bdermato",
        r"(?i)\bpsoriasis\b", r"(?i)\beczéma\b", r"(?i)\bmélanome\b",
        r"(?i)\bcarcinome\s+(basocellulaire|épidermoïde|cutané)",
        r"(?i)\bacné\b", r"(?i)\burticaire\b", r"(?i)\bpemphigoïde\b",
        r"(?i)\bdermatite\s+atopique\b", r"(?i)\bdupilumab\b",
        r"(?i)\bbologène\b", r"(?i)\biksekizumab\b", r"(?i)\bpembrolizumab\b",
        r"(?i)\bguselkumab\b", r"(?i)\bbiologiques?\s+cutanés?",
        r"(?i)\bskin\b", r"(?i)\bdermatol", r"(?i)\batopic dermatitis\b",
        r"(?i)\bpsoriasis\b", r"(?i)\bmelanoma\b", r"(?i)\becz",
        r"(?i)\balopécie\b", r"(?i)\bvitiligo\b", r"(?i)\brosacea\b",
        r"(?i)\bIL.17\b", r"(?i)\bIL.23\b",
    ],
    "endocrinologie": [
        r"(?i)\bdiabète\b", r"(?i)\bthyroïde\b", r"(?i)\bsurrénale\b",
        r"(?i)\bhypophyse\b", r"(?i)\binsuline\b", r"(?i)\bGLP.?1\b",
        r"(?i)\bSGLT.?2\b", r"(?i)\bobésité\b", r"(?i)\bostéoporose\b",
        r"(?i)\bhypothyroïdie\b", r"(?i)\bhyperthyroïdie\b",
        r"(?i)\bHashimoto\b", r"(?i)\bBasedow\b", r"(?i)\bhormone\b",
        r"(?i)\bHbA1c\b", r"(?i)\bglyc[eé]mie\b", r"(?i)\bpancréas\b",
        r"(?i)\bsemaglutide\b", r"(?i)\bdulaglutide\b", r"(?i)\bliraglutide\b",
        r"(?i)\bempagliflozin\b", r"(?i)\bdapagliflozin\b",
        r"(?i)\bmetformine\b", r"(?i)\bsulfonylurée\b",
        r"(?i)diabetes\b", r"(?i)\bthyroid\b", r"(?i)\bobesity\b",
        r"(?i)\binsulin\b", r"(?i)\bhyperglycemia\b", r"(?i)\bA1C\b",
        r"(?i)\bcushing\b", r"(?i)\bacromégalie\b", r"(?i)\bphéochromocytome\b",
    ],
    "gastro-enterologie": [
        r"(?i)\bfoie\b", r"(?i)\bintestin\b", r"(?i)\bcolon\b",
        r"(?i)\brectum\b", r"(?i)\bCrohn\b", r"(?i)\brectocolite\b",
        r"(?i)\bMICI\b", r"(?i)\bhépatite\b", r"(?i)\bcirrhose\b",
        r"(?i)\bulcère\b", r"(?i)\breflux\s+gastro", r"(?i)\bendoscopie\b",
        r"(?i)\bcoloscopie\b", r"(?i)\bpancréas\b", r"(?i)\bcholangite\b",
        r"(?i)\bhémorragie\s+digestive\b", r"(?i)\bdiverticulite\b",
        r"(?i)\bstéatose\b", r"(?i)\bNASH\b", r"(?i)\bMASLD\b",
        r"(?i)\bCBP\b", r"(?i)\bCSP\b", r"(?i)\bIBD\b",
        r"(?i)\bCrohn.s\b", r"(?i)inflammatory bowel\b",
        r"(?i)\bhepatitis\b", r"(?i)\bcirrhosis\b", r"(?i)\bpancreatitis\b",
        r"(?i)\bcolorectal\b", r"(?i)\bgastric\b",
    ],
    "geriatrie": [
        r"(?i)\bpersonne.s?\s+âgée.s?\b", r"(?i)\bgériatri",
        r"(?i)\bdémence\b", r"(?i)\bchute\b", r"(?i)\bfragilité\b",
        r"(?i)\bpolypharmacie\b", r"(?i)\bEHPAD\b", r"(?i)\bdépendance\b",
        r"(?i)\bAlzheimer\b", r"(?i)\bostéoporose\b", r"(?i)\bsarcopénie\b",
        r"(?i)\bdélirium\b", r"(?i)\bdénutrition\s+(gériatrique|âgée)",
        r"(?i)\baging\b", r"(?i)\belderly\b", r"(?i)\bolder adult",
        r"(?i)\bdementia\b", r"(?i)\bfall\b", r"(?i)\bfrailty\b",
        r"(?i)\bnursing home\b", r"(?i)older patient",
    ],
    "gynecologie": [
        r"(?i)\butérus\b", r"(?i)\bovaire\b", r"(?i)\bsein\b",
        r"(?i)\bcol\s+de\s+l.utérus\b", r"(?i)\bménopause\b",
        r"(?i)\bcontraception\b", r"(?i)\bendométriose\b",
        r"(?i)\bgrossesse\b", r"(?i)\bfertilité\b", r"(?i)\bhystérectomie\b",
        r"(?i)\bfibrome\b", r"(?i)\bHPV\b", r"(?i)\bcervical\b",
        r"(?i)\bthérapie\s+hormonale\b", r"(?i)\bTHS\b",
        r"(?i)\bovulation\b", r"(?i)\bmammographie\b", r"(?i)\bFIV\b",
        r"(?i)\bcancer\s+(du\s+sein|ovarien|utérin|endométr)",
        r"(?i)\bbreast cancer\b", r"(?i)\bovarian\b", r"(?i)\buterine\b",
        r"(?i)\bmenopause\b", r"(?i)\bcontraceptive\b",
        r"(?i)\bendometriosis\b", r"(?i)\bfertility\b",
    ],
    "hematologie": [
        r"(?i)\banémie\b", r"(?i)\bleucem", r"(?i)\blymphome\b",
        r"(?i)\bmyélome\b", r"(?i)\bhémophilie\b",
        r"(?i)\bthrombocytopénie\b", r"(?i)\bplaquette\b",
        r"(?i)\bmoelle\s+osseuse\b", r"(?i)\bgreffe\s+(de\s+moelle|hématopo)",
        r"(?i)\btransfusion\b", r"(?i)\bcoagulation\b",
        r"(?i)\banticoagulant\b", r"(?i)\bhémoglobine\b",
        r"(?i)\bdrépanocytose\b", r"(?i)\bthalassémie\b",
        r"(?i)\bmyélofibrose\b", r"(?i)\bLMC\b", r"(?i)\bLLA\b",
        r"(?i)\bLNH\b", r"(?i)\bCAR.T\b", r"(?i)\bleukemia\b",
        r"(?i)\blymphoma\b", r"(?i)\bmyeloma\b", r"(?i)\banemia\b",
        r"(?i)\bhematopoietic\b", r"(?i)\bblood cancer\b",
    ],
    "infectiologie": [
        r"(?i)\binfection\b", r"(?i)\bbactéri", r"(?i)\bviral\b",
        r"(?i)\bantibiotique\b", r"(?i)\bantiviral\b", r"(?i)\bsepsis\b",
        r"(?i)\bpneumonie\b", r"(?i)\btuberculose\b", r"(?i)\bVIH\b",
        r"(?i)\bhépatite\b", r"(?i)\bvaccination\b", r"(?i)\bvaccin\b",
        r"(?i)\bprophylaxie\b", r"(?i)\brésistance\s+aux\s+antibiotiques\b",
        r"(?i)\bépidémie\b", r"(?i)\bfongique\b", r"(?i)\bparasitose\b",
        r"(?i)\bCOVID\b", r"(?i)\bRSV\b", r"(?i)\binfluenza\b",
        r"(?i)\bEBV\b", r"(?i)\bCMV\b", r"(?i)\bHIV\b",
        r"(?i)antimicrobial resistance\b", r"(?i)\bseptic\b",
        r"(?i)\binfectious\b", r"(?i)\bpathogen\b", r"(?i)\bvaccine\b",
        r"(?i)\bATB\b", r"(?i)\bMRSA\b", r"(?i)\bBMR\b",
    ],
    "infirmiers": [
        r"(?i)\bsoins\s+infirmiers\b", r"(?i)\bIDEL\b", r"(?i)\bIDE\b",
        r"(?i)\bpansement\b", r"(?i)\bplaie\b", r"(?i)\bstomie\b",
        r"(?i)\bperfusion\b", r"(?i)\binjection\b", r"(?i)\bcathéter\b",
        r"(?i)\bnursing\b", r"(?i)\binfirmier", r"(?i)\bsoins\s+à\s+domicile\b",
        r"(?i)\bHAD\b", r"(?i)\bescarre\b", r"(?i)\bdouleur.*patient",
        r"(?i)nursing care", r"(?i)wound care", r"(?i)home care",
    ],
    "kinesitherapie": [
        r"(?i)\bkinésithérap", r"(?i)\bphysiothérap", r"(?i)\brééducation\b",
        r"(?i)\bexercice\s+thérapeutique\b", r"(?i)\blombalgie\b",
        r"(?i)\bréhabilitation\b", r"(?i)\bmobilisation\b",
        r"(?i)\bélectrostimulation\b", r"(?i)\bmassage\b",
        r"(?i)\bphysical therapy\b", r"(?i)\brehabilitation\b",
        r"(?i)\bexercise therapy\b", r"(?i)\bmusculoskeletal\b",
        r"(?i)\bmanipulation\b", r"(?i)\bstrengthening\b",
    ],
    "medecine-generale": [
        r"(?i)\bmédecine\s+générale\b", r"(?i)\bmédecin\s+généraliste\b",
        r"(?i)\bsoins\s+primaires\b", r"(?i)\bprévention\b",
        r"(?i)\bdépistage\b", r"(?i)\bvaccination\b", r"(?i)\bcomorbidité\b",
        r"(?i)\bpolymédication\b", r"(?i)\bambulat", r"(?i)\bprimary care\b",
        r"(?i)\bgeneral practice\b", r"(?i)\bGP\b", r"(?i)\bscreening\b",
        r"(?i)\bhypertension\b", r"(?i)\bdiabète\b", r"(?i)\bcholestérol\b",
        r"(?i)\bhypercholestér", r"(?i)\bobésité\b", r"(?i)\bfumeur\b",
        r"(?i)\btabac\b", r"(?i)\bdépression\b", r"(?i)\blombalgie\b",
        r"(?i)\bantibiotique\b",
    ],
    "medecine-interne": [
        r"(?i)\bmédecine\s+interne\b", r"(?i)\bvascularite\b",
        r"(?i)\bsarcoïdose\b", r"(?i)\bamylose\b", r"(?i)\bauto.immune\b",
        r"(?i)\blupus\b", r"(?i)\bSjögren\b", r"(?i)\bpolyarthrite\b",
        r"(?i)\binflammation\s+systémique\b", r"(?i)\bfièvre\s+prolongée\b",
        r"(?i)\bhémopathie\b", r"(?i)\bvascularitis\b",
        r"(?i)systemic\s+(lupus|autoimmune|inflammation)",
        r"(?i)\bsarcoidosis\b", r"(?i)\bamyloidosis\b",
        r"(?i)\bautoimmune\b", r"(?i)\bconnective tissue\b",
    ],
    "medecine-physique": [
        r"(?i)\bMPR\b", r"(?i)\bmédecine\s+physique\b",
        r"(?i)\brééducation\s+(AVC|neurologique|orthopédique)",
        r"(?i)\bspasticité\b", r"(?i)\bparaplégi", r"(?i)\bhandicap\b",
        r"(?i)\bappareillage\b", r"(?i)\blombalgie\b",
        r"(?i)\bdouleur\s+chronique\b", r"(?i)\bfibromyalgie\b",
        r"(?i)\brehabilitation\b", r"(?i)\bneurological rehabilitation\b",
        r"(?i)\bspinal cord\b", r"(?i)\bstroke rehabilitation\b",
        r"(?i)\bprosthesis\b", r"(?i)\borthotics\b",
    ],
    "medecine-urgences": [
        r"(?i)\burgence\b", r"(?i)\bréanimation\b", r"(?i)\btrauma\b",
        r"(?i)\barrêt\s+cardiaque\b", r"(?i)\bRCP\b", r"(?i)\bchoc\b",
        r"(?i)\bsepsis\b", r"(?i)\bpolytraumatisme\b", r"(?i)\bSMUR\b",
        r"(?i)\bintoxication\b", r"(?i)\bAVC\s+aigu\b",
        r"(?i)\baccident\s+vasculaire\s+cérébral\b",
        r"(?i)\btraumatic\b", r"(?i)emergency\b", r"(?i)\bshock\b",
        r"(?i)cardiac arrest\b", r"(?i)\bICU\b", r"(?i)\bcritical care\b",
        r"(?i)\bpre.hospital\b", r"(?i)\bEMS\b", r"(?i)\bresuscitation\b",
    ],
    "nephrologie": [
        r"(?i)\brein\b", r"(?i)\binsufficance\s+rénale\b",
        r"(?i)\binsuffisance\s+rénale\b", r"(?i)\bdialyse\b",
        r"(?i)\btransplantation\s+rénale\b", r"(?i)\bprotéinurie\b",
        r"(?i)\bglomérulonéphrite\b", r"(?i)\bnéphrologie\b",
        r"(?i)\bcréatinine\b", r"(?i)\bDFG\b", r"(?i)\beGFR\b",
        r"(?i)\bhématurie\b", r"(?i)\bdialysis\b", r"(?i)\brenal\b",
        r"(?i)\bkidney\b", r"(?i)\bnephropathy\b", r"(?i)\bproteinuria\b",
        r"(?i)kidney transplant", r"(?i)\bhémodialyse\b",
        r"(?i)\bnéphrotique\b",
    ],
    "neurochirurgie": [
        r"(?i)\bneurochirurgi", r"(?i)\btumeur\s+cérébrale\b",
        r"(?i)\bméningiome\b", r"(?i)\bglioblastome\b",
        r"(?i)\bherniation\s+discale\b", r"(?i)\bhernie\s+discale\b",
        r"(?i)\brachidie\b", r"(?i)\bcraniectomie\b",
        r"(?i)\banévrisme\s+cérébral\b", r"(?i)\bMAV\b",
        r"(?i)\bneurosurger", r"(?i)\bbrain\s+(tumor|surgery)",
        r"(?i)\bspinal surgery\b", r"(?i)\bcraniotomy\b",
        r"(?i)\bdisk herniation\b", r"(?i)\bhydrocephalus\b",
        r"(?i)\bhydrocéphalie\b", r"(?i)\blaminectomie\b",
    ],
    "neurologie": [
        r"(?i)\bAVC\b", r"(?i)\baccident\s+vasculaire\s+cérébral\b",
        r"(?i)\bsclérose\s+en\s+plaques\b", r"(?i)\bSEP\b",
        r"(?i)\bépilepsie\b", r"(?i)\bParkinson\b", r"(?i)\bAlzheimer\b",
        r"(?i)\bmigraine\b", r"(?i)\bneuropathie\b", r"(?i)\bdémence\b",
        r"(?i)\btremblement\b", r"(?i)\bmyasthénie\b",
        r"(?i)\bcerveau\b", r"(?i)\bneurologique\b", r"(?i)\bIRM\s+cérébrale\b",
        r"(?i)\bstroke\b", r"(?i)\bmultiple sclerosis\b",
        r"(?i)\bepilepsy\b", r"(?i)\bneurology\b", r"(?i)\bdementia\b",
        r"(?i)\bneuropathy\b", r"(?i)\bmigraine\b",
        r"(?i)\bnatalizumab\b", r"(?i)\bocrelizumab\b",
    ],
    "oncologie": [
        r"(?i)\bcancer\b", r"(?i)\btumeur\b", r"(?i)\bchimiothérap",
        r"(?i)\bimmunothérap", r"(?i)\banticorps\s+monoclonal",
        r"(?i)\bpembrolizumab\b", r"(?i)\bnivolumab\b",
        r"(?i)\bbevacizumab\b", r"(?i)\bhormono.thérap",
        r"(?i)\bmétastase\b", r"(?i)\bcarcinome\b", r"(?i)\blymphome\b",
        r"(?i)\bsarcome\b", r"(?i)\bchimioth",
        r"(?i)\bsurvie\s+(globale|sans\s+progression)", r"(?i)\bOGS\b",
        r"(?i)\boncologi", r"(?i)\btumor\b", r"(?i)\bmalignant\b",
        r"(?i)\bchemotherapy\b", r"(?i)\bimmunotherapy\b",
        r"(?i)\bcancer\b", r"(?i)\bcheckpoint\s+inhibitor",
        r"(?i)\btargeted therapy\b", r"(?i)\bCAR.T\b",
        r"(?i)\bADC\b", r"(?i)\bantibody.drug conjugate",
    ],
    "ophtalmologie": [
        r"(?i)\bœil\b", r"(?i)\bvision\b", r"(?i)\brétine\b",
        r"(?i)\bglaucome\b", r"(?i)\bcataracte\b", r"(?i)\bDMLA\b",
        r"(?i)\bkératocône\b", r"(?i)\buvéite\b", r"(?i)\bcornée\b",
        r"(?i)\bconjonctivite\b", r"(?i)\bmyopie\b", r"(?i)\bastigmatisme\b",
        r"(?i)\bophtalmologi", r"(?i)\bantiangiogénique\b",
        r"(?i)\banti.VEGF\b", r"(?i)\bintraocular\b",
        r"(?i)\bretinal\b", r"(?i)\bglaucoma\b", r"(?i)\bcataract\b",
        r"(?i)\bAge.related macular\b", r"(?i)\bAMD\b",
        r"(?i)\boptic nerve\b", r"(?i)\bocular\b",
    ],
    "orl": [
        r"(?i)\boreille\b", r"(?i)\bnez\b", r"(?i)\bgorge\b",
        r"(?i)\bsinusite\b", r"(?i)\botite\b", r"(?i)\brhinite\b",
        r"(?i)\blarynx\b", r"(?i)\bpharynx\b", r"(?i)\bvertige\b",
        r"(?i)\bsurdité\b", r"(?i)\btonsill", r"(?i)\bamygdale\b",
        r"(?i)\bapnée\s+du\s+sommeil\b", r"(?i)\bSAOS\b", r"(?i)\bSAS\b",
        r"(?i)\botolaryngol", r"(?i)\bORL\b",
        r"(?i)hearing loss\b", r"(?i)\bsinusitis\b", r"(?i)\brhinitis\b",
        r"(?i)\btinnitus\b", r"(?i)\bvertigo\b", r"(?i)sleep apnea\b",
        r"(?i)\bthyroïde\b.*\bchirurgi", r"(?i)\bparotide\b",
    ],
    "pediatrie": [
        r"(?i)\benfant\b", r"(?i)\bpédiatr", r"(?i)\bnourrisson\b",
        r"(?i)\bnouveau.né\b", r"(?i)\bnéonatal\b", r"(?i)\bcroissance\b",
        r"(?i)\bvaccin\b", r"(?i)\bvaccination\b", r"(?i)\bprématuré\b",
        r"(?i)\bpédiatrique\b", r"(?i)\bpuericulture\b",
        r"(?i)\bchildren\b", r"(?i)\bpediatric\b", r"(?i)\bneonatal\b",
        r"(?i)\binfant\b", r"(?i)\bjuvenile\b", r"(?i)\bchildhood\b",
        r"(?i)\bnewborn\b", r"(?i)\bvaccine.*child",
    ],
    "pharmacien": [
        r"(?i)\bmédicament\b", r"(?i)\bpharmacologi", r"(?i)\binteraction\s+médicament",
        r"(?i)\bpharmacocinétique\b", r"(?i)\bdispensation\b",
        r"(?i)\bofficine\b", r"(?i)\bgénérique\b", r"(?i)\bsubstitution\b",
        r"(?i)\bdéprescription\b", r"(?i)\bpharmacie\b",
        r"(?i)\bdrug.drug interaction", r"(?i)\bpharmacist\b",
        r"(?i)\bprescription\b", r"(?i)\bpolypharmacy\b",
        r"(?i)\bdosage\s+(régime|recommend)", r"(?i)\bbioavailability\b",
        r"(?i)\bAMM\b", r"(?i)\bRCP\s+médicament\b",
    ],
    "pneumologie": [
        r"(?i)\bpoumon\b", r"(?i)\bbronche\b", r"(?i)\basthme\b",
        r"(?i)\bBPCO\b", r"(?i)\bfibrose\s+pulmonaire\b",
        r"(?i)\bpneumonie\b", r"(?i)\btuberculose\b", r"(?i)\bCOVID\b",
        r"(?i)\brespiratoire\b", r"(?i)\bventilation\b",
        r"(?i)\binhalateur\b", r"(?i)\bcorticoïdes\s+inhalés\b",
        r"(?i)\boxygénothérapie\b", r"(?i)\bHTP\b",
        r"(?i)\blung\b", r"(?i)\basthma\b", r"(?i)\bCOPD\b",
        r"(?i)\bpulmonary\b", r"(?i)\brespiratory\b",
        r"(?i)\bpneumonia\b", r"(?i)\binhaler\b",
        r"(?i)\binterstitial lung\b", r"(?i)\bIPF\b",
        r"(?i)\bpulmonary embolism\b", r"(?i)\bémbolie\s+pulmonaire\b",
    ],
    "psychiatrie": [
        r"(?i)\bdépression\b", r"(?i)\banxiété\b", r"(?i)\bbipolaire\b",
        r"(?i)\bschizophrénie\b", r"(?i)\bpsychose\b",
        r"(?i)\bantidépresseur\b", r"(?i)\bantipsychotique\b",
        r"(?i)\banxiolytique\b", r"(?i)\bTOC\b", r"(?i)\bPTSD\b",
        r"(?i)\blithium\b", r"(?i)\baddiction\b",
        r"(?i)\bmental\s+health\b", r"(?i)\bpsychiatri",
        r"(?i)\bdepression\b", r"(?i)\banxiety\b",
        r"(?i)\bschizophrenia\b", r"(?i)\bbipolar\b",
        r"(?i)\bSSRI\b", r"(?i)\bSNRI\b", r"(?i)\bketamine\b",
        r"(?i)\bpsilocybin\b", r"(?i)\btranscranial\b", r"(?i)\bTMS\b",
        r"(?i)\bsuicide\b", r"(?i)\bautisme\b", r"(?i)\bTDA.?H\b",
    ],
    "radiologie": [
        r"(?i)\bimagerie\b", r"(?i)\bIRM\b", r"(?i)\bscanner\b",
        r"(?i)\béchographie\b", r"(?i)\bradiologi", r"(?i)\bTEP.scan\b",
        r"(?i)\binterventionnelle\b", r"(?i)\bémbolisation\b",
        r"(?i)\bartériographie\b", r"(?i)\bcontraste\b",
        r"(?i)\bdose\s+(de\s+rayonnement|d.irradiation)", r"(?i)\bAI\s+radiol",
        r"(?i)\bMRI\b", r"(?i)\bCT\s+scan\b", r"(?i)\bultrasound\b",
        r"(?i)\bradiology\b", r"(?i)\bimaging\b", r"(?i)\bPET\b",
        r"(?i)interventional radiol", r"(?i)\bcontrast\s+agent\b",
    ],
    "rhumatologie": [
        r"(?i)\barthrite\b", r"(?i)\bpolyarthrite\b",
        r"(?i)\bspondylarthrite\b", r"(?i)\blupus\b", r"(?i)\bgoutte\b",
        r"(?i)\bostéoporose\b", r"(?i)\bbiothérapie\b",
        r"(?i)\btocilizumab\b", r"(?i)\badalimumab\b", r"(?i)\banti.TNF\b",
        r"(?i)\bcolchicine\b", r"(?i)\bsyNovite\b", r"(?i)\bcartilage\b",
        r"(?i)\bok itinumab\b", r"(?i)\babatacept\b", r"(?i)\bbaricitinib\b",
        r"(?i)\bupadacitinib\b", r"(?i)\bJAK\s+inhibit",
        r"(?i)\brheumatol", r"(?i)\barthritis\b", r"(?i)\bgout\b",
        r"(?i)\bosteoporosis\b", r"(?i)\bJIA\b", r"(?i)\bspA\b",
        r"(?i)\bPsA\b", r"(?i)\bRA\b.*(?:biologic|DMARDs?)",
        r"(?i)\bfibromyalgie\b",
    ],
    "sage-femme": [
        r"(?i)\bgrossesse\b", r"(?i)\bobstétrique\b", r"(?i)\baccouchement\b",
        r"(?i)\bpérinatale?\b", r"(?i)\bmaternité\b", r"(?i)\bnéonatologie\b",
        r"(?i)\bprématurité\b", r"(?i)\bfœtus\b", r"(?i)\banténatal\b",
        r"(?i)\bpostpartum\b", r"(?i)\béclampsie\b",
        r"(?i)\bhémorragie\s+du\s+post.partum\b", r"(?i)\bdiabète\s+gestationnel\b",
        r"(?i)\bpregnancy\b", r"(?i)\bobstetric\b", r"(?i)\bmaternal\b",
        r"(?i)\bneonatal\b", r"(?i)\bprenatal\b", r"(?i)\bfetal\b",
        r"(?i)\bpreeclampsia\b", r"(?i)\bgestational\b",
    ],
    "urologie": [
        r"(?i)\bprostate\b", r"(?i)\bvésicale?\b", r"(?i)\bvésicale?\b",
        r"(?i)\burinaire\b", r"(?i)\blithiase\b", r"(?i)\bincontinence\b",
        r"(?i)\bcancer\s+de\s+la\s+prostate\b", r"(?i)\bPSA\b",
        r"(?i)\btesticulaire\b", r"(?i)\bhyperplasie\b.*\bprostate\b",
        r"(?i)\brobotic\s+surgery\b", r"(?i)\burologi",
        r"(?i)\bprostate\b", r"(?i)\bbladder\b", r"(?i)\bkidney stone\b",
        r"(?i)\burinary\b", r"(?i)\boveractive bladder\b",
        r"(?i)\bpenile\b", r"(?i)\berectile\b", r"(?i)\btesticular\b",
        r"(?i)\bnephrectomie\b", r"(?i)\bcystoscopie\b",
    ],
}

_SPECIALTY_PREFILTER_RES: dict[str, list[re.Pattern]] = {
    slug: [re.compile(p) for p in patterns]
    for slug, patterns in SPECIALTY_PREFILTER_KEYWORDS.items()
}


# Marqueurs réglementaires transversaux : un article avec ces termes peut concerner
# plusieurs spécialités simultanément → on bypasse le filtre spécialité pour laisser
# le LLM trancher (coût d'un faux-positif ~0.005€, coût d'un faux-négatif = info manquée).
_REGULATORY_BYPASS_RE = re.compile(
    r"(?i)\b("
    r"arr[êe]t[ée]|d[eé]cret|ordonnance|loi\s+n[°o]|circulaire|instruction"
    r"|alerte|retrait|rappel\s+de\s+lot|rupture\s+de\s+stock|p[eé]nurie"
    r"|AMM|ATU|acc[eè]s\s+pr[eé]coce|autorisation\s+de\s+mise\s+en\s+march[eé]"
    r"|JORF|Journal\s+officiel|BO\s+sant[eé]|bulletin\s+officiel"
    r")\b"
)


def specialty_prefilter(title: str, specialty_slug: str, source: str | None = None) -> tuple[bool, str | None]:
    """
    Filtre d'inclusion par spécialité — à appliquer uniquement sur les sources 'tous'.
    Retourne (keep, reason). keep=False si aucun keyword de la spécialité n'est trouvé.

    Bypass automatique pour :
    - Sources de type 'reglementaire' (ANSM, JORF, HAS BO…) — portée nationale multi-spé
    - Titres contenant un marqueur réglementaire explicite (décret, alerte, retrait…)
    """
    # Bypass : source institutionnelle réglementaire (JORF, ANSM, EMA…) → portée nationale
    if source and SOURCE_TO_TYPE.get(source) == "reglementaire":
        return True, None
    # Bypass : marqueur réglementaire dans le titre (toutes sources)
    if _REGULATORY_BYPASS_RE.search(title):
        return True, None
    patterns = _SPECIALTY_PREFILTER_RES.get(specialty_slug)
    if not patterns:
        return True, None  # spécialité sans filtre défini → laisser passer
    if any(p.search(title) for p in patterns):
        return True, None
    return False, f"specialty_mismatch:{specialty_slug}"


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

# ---------------------------------------------------------------------------
# bo_social : allowlist positive — seules les instructions/circulaires/notes
# médicales passent. Les nominations, délégations de signature et compositions
# de commissions RH sont rejetées même si leur titre contient un terme whitelist.
# ---------------------------------------------------------------------------
_BO_SOCIAL_ALLOW_PATTERNS = [
    re.compile(r"(?i)^instruction\b"),
    re.compile(r"(?i)^circulaire\b"),
    re.compile(r"(?i)^note\s+d.information\b"),
    re.compile(r"(?i)\bDGS/"),        # Direction Générale de la Santé
    re.compile(r"(?i)\bDSS/"),        # Direction de la Sécurité Sociale
    re.compile(r"(?i)\bDGOS/"),       # Direction Générale de l'Offre de Soins
    re.compile(r"(?i)\bDREES/"),      # Direction de la Recherche, Études, Évaluation
    re.compile(r"(?i)\bDGCS/"),       # Direction Générale de la Cohésion Sociale (médicosocial)
    re.compile(r"(?i)\bCNAMTS?/"),    # Instructions CNAMTS (convention médicale)
]


def passes_bo_social_allowlist(title: str) -> bool:
    return any(p.search(title) for p in _BO_SOCIAL_ALLOW_PATTERNS)

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


# ---------------------------------------------------------------------------
# ANSM — Filtre opérateur primaire
# ---------------------------------------------------------------------------
# Règle éditoriale : une alerte ANSM (DM ou médicament) ne va à une spécialité
# que si le praticien en est l'opérateur ou le prescripteur PRIMAIRE.
# "Présence au bloc" ne suffit pas — ce filtre est plus strict que specialty_prefilter.
#
# Structure : liste de (pattern_titre, frozenset_specialites_autorisees).
# Si le titre matche un pattern, seules les spécialités listées passent.
# Si aucun pattern ne matche, le filtre ne bloque pas (laisse passer pour évaluation LLM).
# ---------------------------------------------------------------------------

_ANSM_PRIMARY_OP_RULES: list[tuple[re.Pattern, frozenset]] = [

    # ── Instruments électrochirurgicaux généraux (bistouri, pince coupante, coag, trocart) ──
    # Opérateurs : chirurgiens qui tiennent l'instrument. Pas l'anesthésiste.
    (re.compile(
        r"(?i)\bbistouri\b"
        r"|\bélectrochirurgi"
        r"|\bpince\s+coup"
        r"|\bcoagulat(?:eur|ion)\b(?!.*cardiaque)"   # exclure "coagulation sanguine" cardiaque
        r"|\btrocart\b"
        r"|\bagraf(?:e|euse)\b"
        r"|\bstapl(?:er|euse)\b"
        r"|\bdissect(?:eur|ion)\b"
        r"|\bcordotome\b"
    ),
     frozenset({
         "chirurgie-vasculaire", "chirurgie-cardiaque", "chirurgie-orthopedique",
         "chirurgie-pediatrique", "chirurgie-plastique", "chirurgie-thoracique",
         "neurochirurgie", "urologie", "gynecologie", "orl",
     })),

    # ── Garrots chirurgicaux ──
    (re.compile(r"(?i)\bgarrot\b"),
     frozenset({
         "chirurgie-orthopedique", "chirurgie-vasculaire",
         "chirurgie-pediatrique", "chirurgie-plastique",
     })),

    # ── Stimulateurs cardiaques / défibrillateurs / CRT / rythmologie ──
    # Prescripteur primaire = cardiologue/rythmologue.
    # Anesthésie conservée : gestion peropératoire du porteur (règle métier validée).
    (re.compile(
        r"(?i)\bstimulateurs?\s+cardiaque"
        r"|\bpacemaker\b"
        r"|\bdéfibrillateurs?\b"
        r"|\bCRT[-\s]"
        r"|\bICD\b"
        r"|\brythm(?:olog|ique)"
        r"|\bimplantable\s+cardiac"
    ),
     frozenset({
         "chirurgie-cardiaque", "cardiologie", "anesthesiologie", "medecine-urgences",
     })),

    # ── Valves cardiaques / prothèses valvulaires / TAVI ──
    (re.compile(
        r"(?i)\bvalve\b|\bvalvulaire\b"
        r"|\bbioprothèse\s+valv"
        r"|\bTAVI\b|\bTAVR\b"
        r"|\bannuloplastie\b"
        r"|\bprothèse\s+valv"
    ),
     frozenset({"chirurgie-cardiaque", "cardiologie"})),

    # ── Prothèses vasculaires / endoprothèses / filtres cave ──
    (re.compile(
        r"(?i)\bendoprothèse\b"
        r"|\bprothèse\s+aortique\b"
        r"|\bEVAR\b|\bTEVAR\b"
        r"|\bfiltre\s+(?:cave|caval)"
        r"|\bstent\s+(?:périphér|vascu|aort)"
        r"|\bcathéter\s+(?:vascu|artér)"
        r"|\bbypass\s+(?:aorto|fémoro|périph)"
    ),
     frozenset({"chirurgie-vasculaire", "chirurgie-cardiaque", "radiologie"})),

    # ── Prothèses articulaires orthopédiques (hanche, genou, épaule, cheville) ──
    (re.compile(
        r"(?i)\bprothèse\s+(?:totale|de\s+hanche|de\s+genou|d'épaule|articulaire"
        r"|tibiale|fémorale|acétabulaire)\b"
        r"|\btige\s+fémorale\b"
        r"|\bcotyle\b"
        r"|\bimplant\s+orthop"
        r"|\bmatériel\s+ancillaire\b"
        r"|\bancillaire\s+(?:orthop|chirurg)"
    ),
     frozenset({"chirurgie-orthopedique"})),

    # ── Implants rachidiens / neurochirugie ──
    (re.compile(
        r"(?i)\bimplant\s+rachid"
        r"|\bcage\s+intervert"
        r"|\bvis\s+pédiculaire"
        r"|\bprothèse\s+discale\b"
    ),
     frozenset({"neurochirurgie", "chirurgie-orthopedique"})),

    # ── Neurostimulateurs / stimulation cérébrale profonde ──
    (re.compile(
        r"(?i)\bneurostimulateur\b"
        r"|\bstimulat(?:eur|ion)\s+céréb"
        r"|\bDBS\b"
        r"|\bstimulat(?:eur|ion)\s+médullaire\b"
        r"|\bneuropacer\b"
    ),
     frozenset({"neurochirurgie", "neurologie"})),

    # ── Équipements anesthésie / réanimation / voies aériennes ──
    (re.compile(
        r"(?i)\bventilateur\b"
        r"|\brespirat(?:eur|ion\s+artificielle)\b"
        r"|\bBavu\b"
        r"|\bréanimateur\b"
        r"|\bmasque\s+laryngé\b"
        r"|\blaryngoscope\b"
        r"|\bpousse[- ]seringue\b"
        r"|\bperfuseur\b"
        r"|\bvaporis(?:ateur|eur)\s+(?:d')?anesthés"
    ),
     frozenset({"anesthesiologie", "medecine-urgences"})),

    # ── Instruments endoscopiques digestifs (flexible) ──
    # Les instruments de chirurgie laparoscopique/thoracoscopique NE sont PAS ici.
    (re.compile(
        r"(?i)\bendoscope\s+(?:digestif|souple|flexible)\b"
        r"|\bgastroscope\b"
        r"|\bcolosco(?:pe|pie)\b"
        r"|\brectoscope\b"
        r"|\bcystoscope\b"
        r"|\burétéroscope\b"
        r"|\brésectoscope\b"
    ),
     frozenset({"gastro-enterologie", "urologie"})),

    # ── Implants mammaires / chirurgie plastique ──
    (re.compile(
        r"(?i)\bimplant\s+mamm"
        r"|\bprothèse\s+mamm"
        r"|\bimplant\s+pectoral\b"
    ),
     frozenset({"chirurgie-plastique"})),

    # ── DM ophtalmologiques ──
    (re.compile(
        r"(?i)\bimplant\s+(?:oculaire|intraoculaire|rétinien)\b"
        r"|\bIOL\b"
        r"|\bvitrectom"
        r"|\bphaco(?:émulsif)"
    ),
     frozenset({"ophtalmologie"})),

    # ── Médicaments anesthésie (anesthésiques, curares, halogénés) ──
    # Prescripteur exclusif = anesthésiste.
    (re.compile(
        r"(?i)\bpropofol\b"
        r"|\brémifentanil\b"
        r"|\brémifentanil\b"
        r"|\blocuronium\b|\\bvécuronium\b|\batracurium\b|\bcisatracurium\b"
        r"|\bsévoflurane\b|\bisoflurane\b|\bdesflurane\b"
        r"|\bkétamine\s+(?:injectable|IV|anesthés)"
        r"|\bétomidate\b"
        r"|\bsuxaméthonium\b|\bsuccinylcholine\b"
    ),
     frozenset({"anesthesiologie"})),

    # ── Médicaments antipsychotiques / neuroleptiques ──
    (re.compile(
        r"(?i)\brispéridone\b"
        r"|\bhalopéridol\b"
        r"|\bolanzapine\b"
        r"|\bclozapine\b"
        r"|\baripiprazole\b"
        r"|\bquétiapine\b"
        r"|\bpalipéridone\b"
    ),
     frozenset({"psychiatrie", "medecine-generale", "neurologie", "geriatrie"})),

    # ── Biothérapies / chimiothérapies oncologiques ──
    (re.compile(
        r"(?i)\btrastuzumab\b|\bogivri\b|\bherceptin\b"
        r"|\bbevacizumab\b|\bavastin\b"
        r"|\bnivolumab\b|\bopdivu\b"
        r"|\bpembrolizumab\b|\bkeytruda\b"
        r"|\bimatinib\b|\bglivec\b"
        r"|\brituxumab\b|\bmabthera\b"
    ),
     frozenset({"oncologie", "hematologie"})),

    # ── Insuline / analogues / antidiabétiques ──
    (re.compile(
        r"(?i)\binsul(?:ine|in)\b"
        r"|\bglucagon\b"
        r"|\bGLP-1\b"
        r"|\bsemaglutide\b|\bliraglutide\b|\bdulaglutide\b"
        r"|\bexénatide\b"
    ),
     frozenset({
         "endocrinologie", "medecine-generale", "medecine-interne",
         "geriatrie", "pediatrie",
     })),

    # ── Vaccins ──
    (re.compile(r"(?i)\bvaccinat|\bvaccin\b"),
     frozenset({"pediatrie", "medecine-generale", "infectiologie", "geriatrie"})),
]


def ansm_primary_operator_allowed(title: str, specialty_slug: str) -> bool:
    """
    Retourne True si la spécialité est opérateur/prescripteur primaire
    pour le dispositif ou médicament décrit dans le titre ANSM.

    Si aucune règle ne matche → True (pas de restriction, évaluation LLM normale).
    Utilisable depuis les scripts d'insertion manuels pour validation préalable.
    """
    t = (title or "").strip()
    for pattern, allowed_slugs in _ANSM_PRIMARY_OP_RULES:
        if pattern.search(t):
            return specialty_slug in allowed_slugs
    return True  # aucune règle ne s'applique → pas de restriction


def pre_filter_candidate(
    title: str,
    source: str | None = None,
    specialty_slug: str | None = None,
    source_is_tous: bool = False,
) -> tuple[bool, str | None]:
    """Retourne (keep, reason). Si keep=False, pas besoin d'appel LLM.

    specialty_slug + source_is_tous : si la source est une source "tous"
    (applicable à toutes spécialités), le titre doit contenir au moins un
    terme de la spécialité courante, sinon il est éliminé sans appel LLM.
    """
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
    # Filtre opérateur primaire ANSM : un DM ou médicament ANSM ne va qu'à
    # la spécialité dont le praticien est l'opérateur/prescripteur primaire.
    # Plus strict que specialty_prefilter — codé en dur, pas de LLM.
    _ANSM_ALL_SOURCES = _ANSM_SOURCES | {"ansm_securite_dm", "ansm_actualites"}
    if specialty_slug and source in _ANSM_ALL_SOURCES:
        if not ansm_primary_operator_allowed(t, specialty_slug):
            return False, "ansm_not_primary_operator"
    # Filtre spécialité : sources "tous" sans pertinence pour la spé courante
    if specialty_slug and source_is_tous:
        keep, reason = specialty_prefilter(t, specialty_slug, source=source)
        if not keep:
            return False, reason
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
    "mortality", "hospitalization-rate", "complication-free",
    "neurodevelopmental", "infection-rate", "tumor-response",
    "remission-rate", "pain-score", "functional-outcome",
    "seizure-freedom", "graft-survival", "patency", "limb-salvage",
    "stroke-TIA", "reintervention", "composite-MALE", "composite-MACCE",
    "LVEF-function", "valve-durability", "AF-recurrence",
    "technical-success", "quality-of-life", "other",
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
_VALID_GUIDELINE_BODY = {
    # Vasculaire / Cardiaque
    "ESVS", "EACTS", "ESC", "AHA-ACC", "STS", "AATS", "SFC", "SFCTCV", "SFCV", "SFMV",
    # Pédiatrie
    "AAP", "SFP", "IPEG", "EUPSA", "ESPGHAN", "ESPID", "GPIP",
    # Oncologie
    "ESMO", "ASCO",
    # Rhumatologie
    "EULAR", "ACR",
    # Neurologie
    "EAN", "AAN",
    # Pneumologie
    "ERS", "ATS",
    # Urologie
    "EAU",
    # Gastro-entérologie / Hépatologie
    "ECCO", "EASL",
    # Orthopédie
    "EFORT",
    # Institutionnel FR
    "HAS",
    # Catch-all
    "autre",
}
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
