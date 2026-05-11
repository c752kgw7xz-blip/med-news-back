# app/pubmed_collector.py
"""
Collecteur PubMed via NCBI E-utilities.

513 sources configurées couvrant 36 spécialités :
  chirurgie-vasculaire, chirurgie-cardiaque, chirurgie-thoracique,
  chirurgie-orthopedique, chirurgie-plastique, chirurgie-pediatrique,
  chirurgie-pediatrique (urologie), pediatrie, anesthesiologie,
  cardiologie, neurologie, neurochirurgie, psychiatrie, gastro-enterologie,
  hepatologie, pneumologie, infectiologie, rhumatologie, dermatologie,
  endocrinologie, nephrologie, hematologie, oncologie, urologie,
  ophtalmologie, orl, medecine-generale, medecine-interne,
  medecine-urgences, medecine-physique, geriatrie, gynecologie,
  radiologie, biologiste, pharmacien, infirmiers, kinesitherapie, sage-femme

API NCBI E-utilities :
  - esearch.fcgi : recherche par journal_term + date → liste PMIDs
                   retmax=200 (≤35j) ou 500 (>35j — run initial)
  - efetch.fcgi  : détails XML par lots de 20 PMIDs (titre, abstract, DOI, date)

Rate limit NCBI :
  - Sans clé  : 3 req/s  → sleep 0.4s entre lots efetch
  - Avec clé  : 10 req/s → sleep 0.35s (NCBI_API_KEY dans l'env)
  Durée estimée run initial (days=120, 512 sources) : 30-45 minutes.

Sources configurées (voir PUBMED_SOURCES) :

  ── Chirurgie vasculaire ──────────────────────────────────────────────────────
  pubmed_jvs               : Journal of Vascular Surgery
  pubmed_ejves             : European Journal of Vascular and Endovascular Surgery
  pubmed_ejves_guidelines  : EJVES — Guidelines ESVS uniquement
  pubmed_jet               : Journal of Endovascular Therapy
  pubmed_ann_vasc_surg     : Annals of Vascular Surgery
  pubmed_jama_surgery      : JAMA Surgery (RSS 403 depuis avril 2026) — filtré vasculaire

  ── Chirurgie cardiaque ───────────────────────────────────────────────────────
  pubmed_jtcvs             : Journal of Thoracic and Cardiovascular Surgery
  pubmed_ejcts             : European Journal of Cardio-Thoracic Surgery
  pubmed_ejcts_guidelines  : EJCTS — Guidelines EACTS uniquement
  pubmed_ann_thorac_surg   : Annals of Thoracic Surgery
  pubmed_circulation_card  : Circulation (AHA) — filtré chirurgie cardiaque
  pubmed_jacc_card         : Journal of the American College of Cardiology — filtré cardiac
  pubmed_jacc_interv       : JACC Cardiovascular Interventions — filtré cardiac (TAVI, structural)
  pubmed_eur_heart_j       : European Heart Journal — filtré chirurgie cardiaque

  ── Chirurgie plastique & reconstructrice ────────────────────────────────────
  pubmed_prs               : Plastic and Reconstructive Surgery (ASPS flagship)
  pubmed_jpras             : Journal of Plastic, Reconstructive & Aesthetic Surgery (BAPRAS/ESPRAS)
  pubmed_asj               : Aesthetic Surgery Journal (ASAPS)
  pubmed_ann_plast_surg    : Annals of Plastic Surgery
  pubmed_jhs_am            : Journal of Hand Surgery American (ASSH)
  pubmed_jhs_eur           : Journal of Hand Surgery European (FESSH)
  pubmed_jrms              : Journal of Reconstructive Microsurgery
  pubmed_microsurgery      : Microsurgery
  pubmed_burns             : Burns — Elsevier
  pubmed_acpe              : Annales de Chirurgie Plastique Esthétique (SOFCPRE)
  pubmed_prs_guidelines    : PRS — Guidelines ASPS / consensus plastique
  pubmed_jpras_guidelines  : JPRAS — Guidelines BAPRAS/ESPRAS

  ── Chirurgie pédiatrique ─────────────────────────────────────────────────────
  pubmed_jps               : Journal of Pediatric Surgery (IPEG/APSA flagship)
  pubmed_psi               : Pediatric Surgery International (EUPSA/ESPES)
  pubmed_ejps              : European Journal of Pediatric Surgery (EUPSA)
  pubmed_semin_pediatr_surg: Seminars in Pediatric Surgery — Guidelines et consensus
  pubmed_jps_guidelines    : JPS — Guidelines IPEG/APSA/EUPSA publiées dans JPS
  pubmed_jpu               : Journal of Pediatric Urology (ESPU/EAU)
  pubmed_jpu_guidelines    : JPU — Guidelines EAU Pediatric Urology / ESPU

  ── Anesthésiologie / Réanimation / Douleur ──────────────────────────────────
  pubmed_anesthesiology    : Anesthesiology (ASA flagship, IF ~9) — _PT_OR_TITLE
  pubmed_bja               : British Journal of Anaesthesia (AAGBI/RCoA, IF ~9) — _PT_OR_TITLE
  pubmed_anesth_analg      : Anesthesia & Analgesia (IARS, IF ~5) — _PT_OR_TITLE
  pubmed_anaesthesia       : Anaesthesia (AAGBI, IF ~10) — _PT_OR_TITLE
  pubmed_eja               : European Journal of Anaesthesiology (ESAIC, IF ~6) — _PT_OR_TITLE
  pubmed_accpm             : Anaesth Crit Care Pain Med (SFAR officiel) — _PT_OR_TITLE
  pubmed_sfar_guidelines   : SFAR Guidelines (RFE) dans ACCPM — filtre titre
  pubmed_reg_anesth        : Regional Anesthesia and Pain Medicine (ASRA, IF ~8)
  pubmed_intensive_care_med: Intensive Care Medicine (ESICM flagship, IF ~30)
  pubmed_crit_care_med     : Critical Care Medicine (SCCM, IF ~8)
  pubmed_crit_care         : Critical Care (BioMed Central, IF ~15)
  pubmed_jcva              : Journal of Cardiothoracic and Vascular Anesthesia (SOCCA, IF ~5)
  pubmed_acta_anaesthesiol_scand : Acta Anaesthesiologica Scandinavica (SSAI, IF ~4)
  pubmed_can_j_anaesth     : Canadian Journal of Anesthesia (CAS, IF ~4)
  pubmed_pain_iasp         : PAIN (IASP flagship, IF ~7)
  pubmed_j_pain_res        : Journal of Pain Research (open-access)
  pubmed_paediatr_anaesth  : Paediatric Anaesthesia (APAGBI, IF ~3)
"""

from __future__ import annotations

import logging
import os
import time
import xml.etree.ElementTree as ET
from datetime import date, timedelta
from typing import Any

import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn

logger = logging.getLogger(__name__)

NCBI_BASE = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils"
NCBI_API_KEY = os.getenv("NCBI_API_KEY", "")

# ---------------------------------------------------------------------------
# Sources PubMed — journaux dont le RSS éditeur est mort (Elsevier 410 Gone)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Filtre publication type — élimine les séries rétrospectives et case reports
# N'autorise que les types qui peuvent déplacer la pratique :
#   RCT, méta-analyse, revue systématique, guideline, essai phase III, étude multicentrique
# ---------------------------------------------------------------------------
_PT_FILTER = (
    '(("Randomized Controlled Trial"[pt] OR "Meta-Analysis"[pt] OR '
    '"Systematic Review"[pt] OR "Practice Guideline"[pt] OR '
    '"Clinical Trial, Phase III"[pt] OR "Multicenter Study"[pt]) '
    'NOT ("Letter"[pt] OR "Editorial"[pt] OR "Case Reports"[pt] OR "Comment"[pt]))'
)

# Filtre titre en complément de PT_FILTER : capture les articles récents dont les tags
# PubMed ne sont pas encore assignés par les indexeurs NLM (délai 2-6 semaines).
# Utilisé en OR avec PT_FILTER pour les journaux pédiatriques à faible volume.
_TITLE_FILTER = (
    '("meta-analysis"[Title] OR "systematic review"[Title] OR '
    '"randomized"[Title] OR "randomised"[Title] OR '
    '"multicenter"[Title] OR "multicentre"[Title] OR '
    '"multi-center"[Title] OR "multi-centre"[Title] OR '
    '"clinical trial"[Title] OR "guideline"[Title] OR '
    '"consensus"[Title] OR "recommendation"[Title] OR '
    '"position statement"[Title] OR "practice guideline"[Title])'
)

_PT_OR_TITLE = f'({_PT_FILTER} OR {_TITLE_FILTER})'

PUBMED_SOURCES: list[dict] = [

    # ── Journal of Vascular Surgery (JVS) ────────────────────────────────
    # Filtré sur types de publication uniquement — élimine les séries rétrospectives
    # (80 % du journal). Ne remontent que RCTs, méta-analyses, guidelines, études multicentriques.
    # Volume attendu : ~5-10 articles/mois au lieu de ~20.
    {
        "source": "pubmed_jvs",
        "journal_term": f'"J Vasc Surg"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Vascular Surgery (JVS) — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 6,
    },

    # ── European Journal of Vascular and Endovascular Surgery (EJVES) — Innovation ──
    # Même filtre publication type. EJVES publie les grandes études multicentriques
    # européennes (EVAR trials, ACST, carotide) — exactement ce qu'on cherche.
    {
        "source": "pubmed_ejves",
        "journal_term": f'"Eur J Vasc Endovasc Surg"[Journal] AND {_PT_FILTER}',
        "label": "EJVES — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 6,
    },

    # ── EJVES — Guidelines ESVS uniquement (source_type recommandation) ──
    # Filtre titre (guideline, consensus, recommendation…) — pas de filtre pt
    # car les guidelines ESVS sont parfois taguées "Review" ou "Article" sur PubMed.
    {
        "source": "pubmed_ejves_guidelines",
        "journal_term": (
            '"Eur J Vasc Endovasc Surg"[Journal] AND ('
            'guideline[Title] OR consensus[Title] OR recommendation[Title] OR '
            '"clinical practice"[Title] OR "position statement"[Title] OR '
            '"management of"[Title] OR "European Society"[Title]'
            ')'
        ),
        "label": "EJVES — Guidelines ESVS",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 4,
    },

    # ── Journal of Endovascular Therapy (JET) ─────────────────────────────
    # Spécialisé techniques endovasculaires. Filtré sur types de publication :
    # élimine les case series et registres monocentriques qui dominent le journal.
    {
        "source": "pubmed_jet",
        "journal_term": f'"J Endovasc Ther"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Endovascular Therapy (JET) — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 6,
    },

    # ── Annals of Vascular Surgery ────────────────────────────────────────
    # Journal à dominante rétrospective. Volume élevé même avec filtre PT :
    # seuil relevé à 7 pour ne retenir que les études avec impact clinique réel.
    {
        "source": "pubmed_ann_vasc_surg",
        "journal_term": f'"Ann Vasc Surg"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Vascular Surgery — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },

    # ── JAMA Surgery — remplace le RSS 403 depuis avril 2026 ──────────────
    # Double filtre : thématique vasculaire + type de publication.
    # Élimine les études observationnelles chirurgie générale qui n'ont rien à voir.
    {
        "source": "pubmed_jama_surgery",
        "journal_term": (
            '"JAMA Surg"[Journal] AND ('
            '"vascular surgery"[Title/Abstract] OR '
            '"aortic aneurysm"[Title/Abstract] OR '
            '"carotid endarterectomy"[Title/Abstract] OR '
            '"carotid stenosis"[Title/Abstract] OR '
            '"peripheral arterial"[Title/Abstract] OR '
            '"limb ischemia"[Title/Abstract] OR '
            '"endovascular repair"[Title/Abstract] OR '
            '"revascularization"[Title/Abstract] OR '
            '"hemodialysis access"[Title/Abstract] OR '
            '"aortic dissection"[Title/Abstract]'
            f') AND {_PT_FILTER}'
        ),
        "label": "JAMA Surgery — vasculaire, RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # ── CHIRURGIE CARDIAQUE ────────────────────────────────────────────────────
    # ==========================================================================

    # ── Journal of Thoracic and Cardiovascular Surgery (JTCVS) ───────────────
    # Premier journal de référence mondiale en chirurgie cardiaque et thoracique.
    # Publie les grands RCTs (NOTION, SWEDEHEART), méta-analyses CABG vs PCI,
    # études de survie valvulaire, résultats à long terme endoprothèses aortiques.
    # Filtre PT : élimine les séries rétrospectives monocentriques qui dominent le journal.
    {
        "source": "pubmed_jtcvs",
        "journal_term": f'"J Thorac Cardiovasc Surg"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Thoracic and Cardiovascular Surgery (JTCVS) — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── European Journal of Cardio-Thoracic Surgery (EJCTS) — Innovation ─────
    # Homologue européen de JTCVS. Publie les grandes études multicentriques
    # européennes (PARTNER, SURTAVI sub-analyses européennes, études TAVI vs
    # SAVR, pontage à cœur battant). Forum d'expression de l'EACTS.
    {
        "source": "pubmed_ejcts",
        "journal_term": f'"Eur J Cardiothorac Surg"[Journal] AND {_PT_FILTER}',
        "label": "EJCTS — RCTs & méta-analyses",
        "source_type": "innovation",
        # specialty_hint absent → prompt générique (cardiaque + thoracique selon contenu)
        "min_score_hint": 6,
    },

    # ── EJCTS — Guidelines EACTS uniquement (source_type recommandation) ──────
    # Filtre titre : guideline, consensus, recommendation, expert consensus…
    # Les guidelines EACTS sont publiées dans EJCTS joint avec ESC ou en solo.
    # Pas de filtre PT : parfois taguées "Review" ou "Article" sur PubMed.
    {
        "source": "pubmed_ejcts_guidelines",
        "journal_term": (
            '"Eur J Cardiothorac Surg"[Journal] AND ('
            'guideline[Title] OR consensus[Title] OR recommendation[Title] OR '
            '"clinical practice"[Title] OR "position statement"[Title] OR '
            '"expert consensus"[Title] OR "European Association"[Title] OR '
            '"EACTS"[Title] OR "management of"[Title]'
            ')'
        ),
        "label": "EJCTS — Guidelines EACTS",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 4,
    },

    # ── Annals of Thoracic Surgery (Ann Thorac Surg) ─────────────────────────
    # Journal à fort volume rétrospectif (séries de cas, registres monocentriques).
    # Même avec le filtre PT, le niveau moyen est plus bas que JTCVS/EJCTS.
    # Seuil relevé à 7 pour ne retenir que les études à impact clinique réel.
    {
        "source": "pubmed_ann_thorac_surg",
        "journal_term": f'"Ann Thorac Surg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals of Thoracic Surgery — RCTs, méta-analyses & guidelines",
        "source_type": "innovation",
        # specialty_hint absent → prompt générique (cardiaque + thoracique selon contenu)
        "min_score_hint": 7,
    },

    # ── Journal of the American College of Cardiology (JACC) ─────────────────
    # THE journal américain de référence en cardiologie — publie les grandes
    # guidelines ACC/AHA (valvulaire, revascularisation, congénital adulte),
    # RCTs TAVI (Evolut, SAPIEN comparaisons), registres multicentriques.
    # RSS mort (410 Gone) → fallback PubMed. Filtre thématique cardiaque + PT.
    # Volume modéré (6/trim.) mais qualité très haute — min_score 6.
    {
        "source": "pubmed_jacc_card",
        "journal_term": (
            '"J Am Coll Cardiol"[Journal] AND ('
            '"cardiac surgery"[Title/Abstract] OR '
            '"coronary artery bypass"[Title/Abstract] OR '
            '"CABG"[Title/Abstract] OR '
            '"aortic valve"[Title/Abstract] OR '
            '"mitral valve"[Title/Abstract] OR '
            '"tricuspid valve"[Title/Abstract] OR '
            '"TAVI"[Title/Abstract] OR '
            '"TAVR"[Title/Abstract] OR '
            '"transcatheter"[Title/Abstract] OR '
            '"structural heart"[Title/Abstract] OR '
            '"ventricular assist device"[Title/Abstract] OR '
            '"heart transplantation"[Title/Abstract] OR '
            '"aortic dissection"[Title/Abstract]'
            f') AND {_PT_FILTER}'
        ),
        "label": "JACC — Journal of the American College of Cardiology (cardiac surgery + structural)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── JACC Cardiovascular Interventions ────────────────────────────────────
    # Sous-journal JACC spécialisé interventionnel — publie les grands RCTs
    # structural heart : TAVI (PARTNER, Evolut), TEER (CLASP, TRILUMINATE),
    # coronaire (PCI vs CABG sub-analyses), assistance circulatoire percutanée.
    # C'est LE journal des Heart Teams pour les décisions TAVI vs SAVR.
    # RSS mort → PubMed. Volume excellent (17/trim.) — min_score 6.
    {
        "source": "pubmed_jacc_interv",
        "journal_term": (
            '"JACC Cardiovasc Interv"[Journal] AND ('
            '"aortic valve"[Title/Abstract] OR '
            '"mitral valve"[Title/Abstract] OR '
            '"tricuspid valve"[Title/Abstract] OR '
            '"TAVI"[Title/Abstract] OR '
            '"TAVR"[Title/Abstract] OR '
            '"transcatheter"[Title/Abstract] OR '
            '"structural heart"[Title/Abstract] OR '
            '"cardiac surgery"[Title/Abstract] OR '
            '"coronary artery bypass"[Title/Abstract] OR '
            '"CABG"[Title/Abstract] OR '
            '"ventricular assist"[Title/Abstract]'
            f') AND {_PT_FILTER}'
        ),
        "label": "JACC Cardiovascular Interventions — TAVI, structural heart, PCI vs CABG",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── European Heart Journal (ESC flagship) ────────────────────────────────
    # Journal officiel de l'ESC — publie les grands essais pivots qui alimentent
    # directement les guidelines ESC/EACTS : LVAD (MOMENTUM 3 extensions),
    # rejet greffe cardiaque, TAVI sex-specific outcomes, CABG multi-tronculaire.
    # RSS mort (Elsevier/Oxford) → PubMed. Volume (7/trim.) mais qualité maximale.
    {
        "source": "pubmed_eur_heart_j",
        "journal_term": (
            '"Eur Heart J"[Journal] AND ('
            '"cardiac surgery"[Title/Abstract] OR '
            '"coronary artery bypass"[Title/Abstract] OR '
            '"CABG"[Title/Abstract] OR '
            '"aortic valve"[Title/Abstract] OR '
            '"mitral valve"[Title/Abstract] OR '
            '"tricuspid valve"[Title/Abstract] OR '
            '"TAVI"[Title/Abstract] OR '
            '"TAVR"[Title/Abstract] OR '
            '"transcatheter"[Title/Abstract] OR '
            '"structural heart"[Title/Abstract] OR '
            '"ventricular assist device"[Title/Abstract] OR '
            '"heart transplantation"[Title/Abstract] OR '
            '"aortic dissection"[Title/Abstract] OR '
            '"myocardial revascularization"[Title/Abstract]'
            f') AND {_PT_FILTER}'
        ),
        "label": "European Heart Journal (ESC) — cardiac surgery & structural heart",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── Circulation (AHA) — chirurgie cardiaque ──────────────────────────────
    # Journal de l'American Heart Association — publie en priorité les grands essais
    # cardiaques : EXCEL (CABG vs PCI left main), PARTNER long-term (TAVI), TEER
    # tricuspide, RCT LVAD. Pas de RSS Elsevier → fallback PubMed.
    # Double filtre thématique (cardiac surgery + valvulaire + coronaire) + PT.
    # Seuil min_score 7 : sélection déjà très stricte par le filtre.
    {
        "source": "pubmed_circulation_card",
        "journal_term": (
            '"Circulation"[Journal] AND ('
            '"cardiac surgery"[Title/Abstract] OR '
            '"coronary artery bypass"[Title/Abstract] OR '
            '"CABG"[Title/Abstract] OR '
            '"aortic valve"[Title/Abstract] OR '
            '"mitral valve"[Title/Abstract] OR '
            '"tricuspid valve"[Title/Abstract] OR '
            '"TAVI"[Title/Abstract] OR '
            '"TAVR"[Title/Abstract] OR '
            '"heart valve"[Title/Abstract] OR '
            '"left main revascularization"[Title/Abstract] OR '
            '"ventricular assist device"[Title/Abstract] OR '
            '"heart transplantation"[Title/Abstract] OR '
            '"aortic dissection"[Title/Abstract]'
            f') AND {_PT_FILTER}'
        ),
        "label": "Circulation (AHA) — cardiaque, RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 7,
    },

    # ── Journal of Heart and Lung Transplantation (JHLT) ─────────────────────
    # Journal de référence mondial transplant cardiaque + MCS/LVAD/TMCS.
    # Publie : RCTs LVAD, registres ISHLT, guidelines transplant, études bridging.
    # Journal 100 % ciblé → pas de filtre thématique supplémentaire.
    # Volume : ~21 articles/90j. Min_score 6 (niveau de preuve élevé dans ce journal).
    {
        "source": "pubmed_jhlt",
        "journal_term": f'"J Heart Lung Transplant"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Heart and Lung Transplantation — transplant & LVAD",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── EuroIntervention (PCR) ────────────────────────────────────────────────
    # Journal de référence européen pour l'interventionnel structurel cardiaque.
    # Publie : essais TAVI, TEER, occlusion auricule, cardio-oncologie interventionnelle.
    # Filtre thématique cardiac structural — exclut coronaire pur et péricardique.
    # Volume : ~8 articles/90j. Min_score 6.
    {
        "source": "pubmed_eurointerv",
        "journal_term": (
            '"EuroIntervention"[Journal] AND ('
            '"TAVI"[tiab] OR "TAVR"[tiab] OR "transcatheter"[tiab] OR '
            '"aortic valve"[tiab] OR "mitral valve"[tiab] OR "tricuspid"[tiab] OR '
            '"structural heart"[tiab] OR "left atrial appendage"[tiab] OR '
            '"TEER"[tiab] OR "edge-to-edge"[tiab] OR "valve-in-valve"[tiab] OR '
            '"cardiac surgery"[tiab] OR "coronary artery bypass"[tiab]'
            f') AND {_PT_FILTER}'
        ),
        "label": "EuroIntervention (PCR) — structural heart & TAVI européen",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── Circulation: Heart Failure (AHA) ─────────────────────────────────────
    # Journal AHA dédié à l'insuffisance cardiaque avancée.
    # Publie : essais LVAD (MOMENTUM 3, ENDURANCE), registres MCS, études transplant,
    # nouvelles thérapies IC terminale. Journal ciblé → pas de filtre thématique.
    # Volume : ~9 articles/90j. Min_score 6.
    {
        "source": "pubmed_circ_heart_fail",
        "journal_term": f'"Circ Heart Fail"[Journal] AND {_PT_FILTER}',
        "label": "Circulation: Heart Failure — LVAD, MCS, transplant, IC avancée",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 6,
    },

    # ── ESC Guidelines (via European Heart Journal + Eur J Heart Fail) ───────
    # Les guidelines ESC sont publiées dans EHJ et Eur J Heart Fail.
    # PubMed ne les tague pas systématiquement "Practice Guideline"[pt] →
    # on filtre par titre (guideline, consensus, recommendation, position statement).
    # Volume très faible (~3/180j) mais chaque document = guideline ESC complet.
    # Min_score 4 — sélection sur pertinence cardiaque chirurgicale en aval.
    {
        "source": "pubmed_esc_guidelines",
        "journal_term": (
            '("Eur Heart J"[Journal] OR "Eur J Heart Fail"[Journal] OR '
            '"Eur Heart J Cardiovasc Imaging"[Journal]) AND '
            '(guideline[Title] OR "consensus document"[Title] OR '
            '"position statement"[Title] OR "expert consensus"[Title] OR '
            '"ESC Guidelines"[Title] OR "management of"[Title] OR '
            '"recommendations for"[Title])'
        ),
        "label": "ESC Guidelines — EHJ / Eur J Heart Fail / EHJCI",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 4,
    },

    # ── STS Guidelines (via Annals of Thoracic Surgery) ──────────────────────
    # Les guidelines STS (Society of Thoracic Surgeons) sont publiées dans
    # Ann Thorac Surg et Ann Thorac Surg Short Reports.
    # Filtre titre guideline + STS/Society of Thoracic Surgeons.
    # Volume faible (~3/180j) mais haute valeur réglementaire US (souvent adoptés en EU).
    # Min_score 4.
    {
        "source": "pubmed_sts_guidelines",
        "journal_term": (
            '"Ann Thorac Surg"[Journal] AND ('
            'guideline[Title] OR "STS guideline"[Title] OR '
            '"Society of Thoracic Surgeons"[tiab] OR '
            '"consensus statement"[Title] OR "position statement"[Title] OR '
            '"expert consensus"[Title] OR "expert panel"[Title]'
            ')'
        ),
        "label": "STS Guidelines — Annals of Thoracic Surgery",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-cardiaque",
        "min_score_hint": 4,
    },

    # ── Chirurgie thoracique — journaux innovation ───────────────────────────
    # Seuil 7 pour JTO (IF ~20, IASLC — journal de référence cancer poumon opéré).
    # Seuil 6 pour les autres : volume suffisant, filtre addendum strict.
    {
        "source": "pubmed_jto",
        "journal_term": f'"J Thorac Oncol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Thoracic Oncology (JTO) — IASLC",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_lung_cancer_thorac",
        "journal_term": f'"Lung Cancer"[Journal] AND {_PT_OR_TITLE}',
        "label": "Lung Cancer — IASLC affiliated (NSCLC résécable + systémique)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_dis_esophagus",
        "journal_term": f'"Dis Esophagus"[Journal] AND {_PT_FILTER}',
        "label": "Diseases of the Esophagus — ISDE",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    # pubmed_icvts SUPPRIMÉ : ICVTS a fusionné avec EJCTS en janvier 2023,
    # plus aucune publication depuis 2022. Couvert désormais par pubmed_ejcts.
    {
        "source": "pubmed_semin_thorac",
        # Seminars publie des reviews invitées — ni RCT ni meta-analyse dans le titre.
        # Pas de _PT_FILTER ni _PT_OR_TITLE : on collecte tout, le LLM score filtre.
        "journal_term": '"Semin Thorac Cardiovasc Surg"[Journal] NOT ("Letter"[pt] OR "Editorial"[pt] OR "Comment"[pt])',
        "label": "Seminars in Thoracic and Cardiovascular Surgery — reviews majeures",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    # Chest (ACCP) — IF ~9, très large couverture : maladie pleurale,
    # bilan pré-op respiratoire, cancer bronchique, interventionnel.
    # Volume important → filtre PT strict.
    {
        "source": "pubmed_chest",
        "journal_term": f'"Chest"[Journal] AND {_PT_FILTER}',
        "label": "Chest — American College of Chest Physicians (ACCP)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    # Thorax (BTS/BMJ) — IF ~10 : maladie pleurale, cancer poumon, empyème,
    # pneumothorax, résultats chirurgicaux UK.
    {
        "source": "pubmed_thorax_bts",
        "journal_term": f'"Thorax"[Journal] AND {_PT_FILTER}',
        "label": "Thorax — British Thoracic Society / BMJ",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    # EJSO + filtre thoracique — oncologie chirurgicale poumon/œsophage/thymome.
    {
        "source": "pubmed_ejso_thorac",
        "journal_term": (
            '"Eur J Surg Oncol"[Journal] AND ('
            'lung[tiab] OR pulmonary[tiab] OR esophageal[tiab] OR '
            'oesophageal[tiab] OR thoracic[tiab] OR mesothelioma[tiab] OR '
            'thymoma[tiab] OR NSCLC[tiab] OR lobectomy[tiab] OR '
            'esophagectomy[tiab]'
            f') AND {_PT_FILTER}'
        ),
        "label": "European Journal of Surgical Oncology — filtre thoracique",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    # Ann Surg Oncol + filtre thoracique — métastasectomie pulmonaire,
    # cancer œsophage résécable, thymome.
    {
        "source": "pubmed_ann_surg_oncol_thorac",
        "journal_term": (
            '"Ann Surg Oncol"[Journal] AND ('
            'lung[tiab] OR pulmonary[tiab] OR esophageal[tiab] OR '
            'oesophageal[tiab] OR thoracic[tiab] OR mesothelioma[tiab] OR '
            'thymoma[tiab] OR metastasectomy[tiab] OR NSCLC[tiab] OR '
            'lobectomy[tiab] OR esophagectomy[tiab]'
            f') AND {_PT_FILTER}'
        ),
        "label": "Annals of Surgical Oncology — filtre thoracique",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 6,
    },
    # JTCVS + filtre thoracique — résection pulmonaire, œsophage, thymome,
    # plèvre. Distinct du slug pubmed_jtcvs (mappé chirurgie-cardiaque).
    {
        "source": "pubmed_jtcvs_thorac",
        "journal_term": (
            '"J Thorac Cardiovasc Surg"[Journal] AND ('
            'lobectomy[tiab] OR segmentectomy[tiab] OR pneumonectomy[tiab] OR '
            'esophagectomy[tiab] OR thymectomy[tiab] OR '
            '"lung resection"[tiab] OR "pulmonary resection"[tiab] OR '
            'VATS[tiab] OR RATS[tiab] OR thoracoscopic[tiab] OR '
            'pleural[tiab] OR mediastinal[tiab] OR mesothelioma[tiab]'
            f') AND {_PT_OR_TITLE}'
        ),
        "label": "JTCVS — filtre chirurgie thoracique (résection / œsophage / plèvre)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 7,
    },
    # ── Chirurgie thoracique — guidelines / recommandations ──────────────────
    # ESTS guidelines publiées principalement dans EJCTS.
    # Filtre titre guideline + "European Society of Thoracic Surgeons".
    {
        "source": "pubmed_ests_guidelines",
        "journal_term": (
            '"Eur J Cardiothorac Surg"[Journal] AND ('
            'guideline[Title] OR "ESTS guideline"[Title] OR '
            '"European Society of Thoracic Surgeons"[tiab] OR '
            '"consensus statement"[Title] OR "position statement"[Title] OR '
            '"expert consensus"[Title] OR "expert panel"[Title]'
            ')'
        ),
        "label": "ESTS Guidelines — European Journal of Cardio-Thoracic Surgery",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-thoracique",
        "min_score_hint": 4,
    },

    # BTS guidelines publiées dans Thorax (BMJ).
    # Filtre : guideline ou "British Thoracic Society" dans titre/abstract.
    # Cross-specialty : pneumologie ET chirurgie-thoracique selon contenu.
    {
        "source": "pubmed_bts_guidelines",
        "journal_term": (
            '"Thorax"[Journal] AND ('
            'guideline[Title] OR "British Thoracic Society"[tiab] OR '
            '"BTS guideline"[tiab] OR "consensus statement"[Title] OR '
            '"position statement"[Title] OR "expert panel"[Title] OR '
            '"clinical practice guideline"[Title]'
            ')'
        ),
        "label": "BTS Guidelines — Thorax / British Thoracic Society",
        "source_type": "recommandation",
        # specialty_hint absent → prompt générique (pneumologie + chirurgie-thoracique)
        "min_score_hint": 4,
    },
    # ESMO guidelines thoraciques publiées dans Annals of Oncology.
    # Filtre : contenu lung/esophage/thoracique + guideline dans titre.
    # Cross-specialty : oncologie ET chirurgie-thoracique selon degré chirurgical.
    {
        "source": "pubmed_esmo_thorac_guidelines",
        "journal_term": (
            '"Ann Oncol"[Journal] AND ('
            'lung[tiab] OR NSCLC[tiab] OR SCLC[tiab] OR esophageal[tiab] OR '
            'oesophageal[tiab] OR mesothelioma[tiab] OR thoracic[tiab]'
            ') AND ('
            'guideline[Title] OR "clinical practice guideline"[Title] OR '
            '"ESMO"[tiab] OR consensus[Title] OR "position paper"[Title] OR '
            '"expert consensus"[Title] OR "management of"[Title]'
            ')'
        ),
        "label": "ESMO Guidelines thoraciques — Annals of Oncology",
        "source_type": "recommandation",
        # specialty_hint absent → prompt générique (oncologie + chirurgie-thoracique)
        "min_score_hint": 4,
    },

    # ── Chirurgie orthopédique — journaux innovation ──────────────────────────
    # Seuil 7 par défaut : équivalent chirurgie cardiaque, ajustable après retour.
    {
        "source": "pubmed_jbjs",
        "journal_term": f'"J Bone Joint Surg Am"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Bone & Joint Surgery (Am) — JBJS",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_bone_joint_j",
        "journal_term": f'"Bone Joint J"[Journal] AND {_PT_FILTER}',
        "label": "Bone & Joint Journal (BJJ/JBJS Br) — EFORT flagship",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_corr",
        "journal_term": f'"Clin Orthop Relat Res"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Orthopaedics and Related Research (CORR)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_jarthroplasty",
        "journal_term": f'"J Arthroplasty"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Arthroplasty — prothèses hanche/genou",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_kssta",
        "journal_term": f'"Knee Surg Sports Traumatol Arthrosc"[Journal] AND {_PT_FILTER}',
        "label": "Knee Surgery Sports Traumatology Arthroscopy (KSSTA) — ESSKA",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_acta_orthop",
        "journal_term": f'"Acta Orthop"[Journal] AND {_PT_FILTER}',
        "label": "Acta Orthopaedica — Nordic Orthopaedic Federation",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    # ── Chirurgie du sport / arthroscopie ────────────────────────────────────
    {
        "source": "pubmed_ajsm",
        "journal_term": f'"Am J Sports Med"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Sports Medicine (AJSM) — AOSSM",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_arthroscopy",
        "journal_term": f'"Arthroscopy"[Journal] AND {_PT_FILTER}',
        "label": "Arthroscopy — Journal of Arthroscopic and Related Surgery",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    # ── Sous-spécialités ortho ────────────────────────────────────────────────
    {
        "source": "pubmed_jses",
        "journal_term": f'"J Shoulder Elbow Surg"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Shoulder and Elbow Surgery (JSES)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_spine",
        "journal_term": f'"Spine (Phila Pa 1976)"[Journal] AND {_PT_FILTER}',
        "label": "Spine — Wolters Kluwer",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_j_orthop_trauma",
        "journal_term": f'"J Orthop Trauma"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Orthopaedic Trauma",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    # ── Journaux européens complémentaires ───────────────────────────────────
    {
        "source": "pubmed_int_orthop",
        "journal_term": f'"Int Orthop"[Journal] AND {_PT_FILTER}',
        "label": "International Orthopaedics (SICOT)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_arch_orthop_trauma",
        "journal_term": f'"Arch Orthop Trauma Surg"[Journal] AND {_PT_FILTER}',
        "label": "Archives of Orthopaedic and Trauma Surgery",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 6,
    },
    # ==========================================================================
    # ── CHIRURGIE PLASTIQUE & RECONSTRUCTRICE ─────────────────────────────────
    # ==========================================================================

    # ── Plastic and Reconstructive Surgery (PRS) — ASPS flagship ─────────────
    # Journal de référence mondial : reconstruction mammaire, microchirurgie,
    # lambeaux libres, chirurgie esthétique. Publie les RCTs multicentriques ASPS,
    # méta-analyses DIEP vs TRAM, essais randomisés liposuccion/abdominoplastie.
    # _PT_OR_TITLE : NLM tague les PT avec 2-6 semaines de retard → fenêtre 4j quasi-vide sans title fallback.
    {
        "source": "pubmed_prs",
        "journal_term": f'"Plast Reconstr Surg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Plastic and Reconstructive Surgery (PRS) — ASPS flagship",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 7,
    },

    # ── Journal of Plastic, Reconstructive & Aesthetic Surgery (JPRAS) ────────
    # Organe officiel BAPRAS (British) et forum ESPRAS (European). Publie les
    # grandes études européennes multicentrique : brûlures, reconstruction post-
    # oncologique, chirurgie de la main, microchirurgie reconstructrice.
    {
        "source": "pubmed_jpras",
        "journal_term": f'"J Plast Reconstr Aesthet Surg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Plastic, Reconstructive & Aesthetic Surgery (JPRAS) — BAPRAS/ESPRAS",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 7,
    },

    # ── Aesthetic Surgery Journal (ASJ) — ASAPS ───────────────────────────────
    # Journal référence chirurgie esthétique : rhinoplastie, mammoplastie, lifting,
    # liposuccion. Publie guidelines ASAPS, essais randomisés implants, méta-analyses
    # techniques esthétiques. Contexte fortement US mais largement lu en France.
    {
        "source": "pubmed_asj",
        "journal_term": f'"Aesthet Surg J"[Journal] AND {_PT_OR_TITLE}',
        "label": "Aesthetic Surgery Journal (ASJ) — ASAPS",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 7,
    },

    # ── Annals of Plastic Surgery ─────────────────────────────────────────────
    # Journal Wolters Kluwer à fort volume rétrospectif. Même avec filtre PT,
    # niveau moyen plus bas que PRS/JPRAS. Seuil relevé à 8 : ne retenir que
    # les méta-analyses à fort impact ou études multicentriques pivots.
    {
        "source": "pubmed_ann_plast_surg",
        "journal_term": f'"Ann Plast Surg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals of Plastic Surgery",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 8,
    },

    # ── Journal of Hand Surgery — American (ASSH) ─────────────────────────────
    # Référence mondiale chirurgie de la main. En France la chirurgie de la main
    # est exercée principalement par les chirurgiens plasticiens reconstructeurs.
    # Publie RCTs tendons, nerfs, arthrose digitale, réimplantations, syndactylie.
    {
        "source": "pubmed_jhs_am",
        "journal_term": f'"J Hand Surg Am"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Hand Surgery American (ASSH) — chirurgie de la main",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 7,
    },

    # ── Journal of Hand Surgery — European (FESSH) ────────────────────────────
    # Homologue européen — publie les grandes séries européennes (registres
    # nordiques, études FESSH multicentriques) sur tendon, nerf, arthroplastie
    # digitale, traumatologie sévère de la main.
    {
        "source": "pubmed_jhs_eur",
        "journal_term": f'"J Hand Surg Eur Vol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Hand Surgery European (FESSH)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 6,
    },

    # ── Journal of Reconstructive Microsurgery (JRM) ──────────────────────────
    # Journal dédié microchirurgie reconstructrice : lambeaux libres (DIEP, ALT,
    # fibula), replantations, transferts nerveux, lymphœdème microsurgical.
    # Journal ciblé → pas de filtre thématique additionnel.
    {
        "source": "pubmed_jrms",
        "journal_term": f'"J Reconstr Microsurg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Reconstructive Microsurgery (JRM)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 6,
    },

    # ── Microsurgery ──────────────────────────────────────────────────────────
    # Journal spécialisé microchirurgie (Wiley). Publie études sur perforateurs,
    # cartographie MSCT, techniques anastomose, lymphœdème microsurgical (LYMPHA,
    # LVA), transfert vascularisé ganglionnaire lymphatique.
    {
        "source": "pubmed_microsurgery",
        "journal_term": f'"Microsurgery"[Journal] AND {_PT_OR_TITLE}',
        "label": "Microsurgery — Wiley",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 6,
    },

    # ── Burns (Elsevier) ──────────────────────────────────────────────────────
    # Journal international de référence pour la prise en charge des brûlures.
    # Publie RCTs pansements, greffes en maille, substituts cutanés (MatriDerm,
    # Integra), protocoles de réhabilitation, épidémiologie centres brûlés.
    {
        "source": "pubmed_burns",
        "journal_term": f'"Burns"[Journal] AND {_PT_OR_TITLE}',
        "label": "Burns — International Journal of Burn Care (Elsevier)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 6,
    },

    # ── Annales de Chirurgie Plastique Esthétique (ACPE) — SOFCPRE ───────────
    # Journal officiel de la SOFCPRE (Société Française de Chirurgie Plastique
    # Reconstructrice et Esthétique). Publie études françaises multicentriques,
    # recommandations SOFCPRE, registres implants mammaires PIP-post. Bilinguisme.
    # Seuil 6 : contexte français fort, même études de niveau moyen sont pertinentes.
    {
        "source": "pubmed_acpe",
        "journal_term": f'"Ann Chir Plast Esthet"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annales de Chirurgie Plastique Esthétique (ACPE) — SOFCPRE",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 6,
    },

    # ── Chirurgie plastique — guidelines / recommandations ────────────────────

    # PRS Guidelines — ASPS / consensus plastique
    # Filtre titre : guideline, consensus, recommendation, position statement,
    # clinical practice, systematic review ayant valeur de recommandation.
    # Les guidelines ASPS (Breast Implant Safety, DIEP best practice, etc.)
    # sont publiées dans PRS en tant qu'articles de société.
    {
        "source": "pubmed_prs_guidelines",
        "journal_term": (
            '"Plast Reconstr Surg"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "expert opinion"[Title] OR '
            '"clinical practice"[Title] OR "best practice"[Title] OR '
            '"ASPS"[Title] OR "American Society of Plastic Surgeons"[Title] OR '
            '"practice advisory"[Title]'
            ')'
        ),
        "label": "PRS Guidelines — ASPS recommandations & consensus plastique",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 4,
    },

    # JPRAS Guidelines — BAPRAS / ESPRAS recommandations
    {
        "source": "pubmed_jpras_guidelines",
        "journal_term": (
            '"J Plast Reconstr Aesthet Surg"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "expert opinion"[Title] OR '
            '"clinical practice"[Title] OR "best practice"[Title] OR '
            '"BAPRAS"[Title] OR "ESPRAS"[Title] OR "ISAPS"[Title] OR '
            '"systematic review"[Title]'
            ')'
        ),
        "label": "JPRAS Guidelines — BAPRAS / ESPRAS recommandations plastique",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 4,
    },

    # ── Plastic and Reconstructive Surgery Global Open (PRS GO) — ASPS ────────
    # Companion open-access de PRS. Les RCTs et méta-analyses qui ne passent pas
    # la barre éditoriale de PRS atterrissent ici. Volume plus élevé que PRS
    # avec IF ~2 (vs PRS IF ~5) — filtre PT identique, seuil 7 pour ne retenir
    # que les études ayant un impact clinique réel malgré le rang plus bas.
    {
        "source": "pubmed_prs_global_open",
        "journal_term": f'"Plast Reconstr Surg Glob Open"[Journal] AND {_PT_OR_TITLE}',
        "label": "Plastic and Reconstructive Surgery Global Open (ASPS open access)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 7,
    },

    # ── Wound Repair and Regeneration (WRR) — Wiley ───────────────────────────
    # Journal de référence en biologie de la cicatrisation et médecine régénérative.
    # Publie les essais randomisés sur substituts dermiques (Integra, MatriDerm,
    # NPWT, RECELL), protocols de cicatrisation des brûlures et plaies chroniques,
    # techniques de greffe cutanée. Central pour les plasticiens reconstructeurs
    # et les chirurgiens des brûlures.
    # Filtre PT : élimine les travaux fondamentaux (mécanismes cellulaires,
    # modèles murins) qui dominent le journal mais sans intérêt clinique direct.
    {
        "source": "pubmed_wound_repair",
        "journal_term": f'"Wound Repair Regen"[Journal] AND {_PT_FILTER}',
        "label": "Wound Repair and Regeneration (WRR) — Wiley",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-plastique",
        "min_score_hint": 6,
    },

    # OTSR = journal officiel SOFCOT — bilinguisme FR/EN, haut contexte français
    {
        "source": "pubmed_otsr",
        "journal_term": f'"Orthop Traumatol Surg Res"[Journal] AND {_PT_FILTER}',
        "label": "Orthopaedics & Traumatology Surgery & Research (OTSR) — SOFCOT",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 6,
    },

    # ── Chirurgie orthopédique — guidelines / recommandations ─────────────────
    # Filtre titre plutôt que PT : les guidelines ortho ne sont pas systématiquement
    # taguées "Practice Guideline"[pt] dans PubMed.
    {
        "source": "pubmed_otsr_guidelines",
        "journal_term": (
            '"Orthop Traumatol Surg Res"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "expert opinion"[Title] OR '
            '"clinical practice"[Title] OR "best practice"[Title]'
            ')'
        ),
        "label": "OTSR Guidelines — SOFCOT recommandations",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 4,
    },
    {
        "source": "pubmed_efort_guidelines",
        "journal_term": (
            '"EFORT Open Rev"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "expert opinion"[Title] OR '
            '"clinical practice"[Title] OR "best practice"[Title] OR '
            '"systematic review"[Title] OR "meta-analysis"[Title]'
            ')'
        ),
        "label": "EFORT Open Reviews — Guidelines européennes ortho",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 4,
    },

    # ==========================================================================
    # ── CHIRURGIE PÉDIATRIQUE ─────────────────────────────────────────────────
    # ==========================================================================

    # ── Journal of Pediatric Surgery (JPS) — IPEG/APSA/CAPS flagship ─────────
    # Journal de référence mondial en chirurgie pédiatrique. Publie les RCTs
    # multicentriques APSA, méta-analyses IPEG (laparoscopie pédiatrique),
    # essais sur appendicite, hernie inguinale, sténose hypertrophique du pylore,
    # malformations congénitales (atrésie œsophagienne, hernie diaphragmatique).
    # Filtre PT : élimine les séries rétrospectives mono-centriques.
    {
        "source": "pubmed_jps",
        "journal_term": f'"J Pediatr Surg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Pediatric Surgery (JPS) — IPEG/APSA flagship",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 7,
    },

    # ── Pediatric Surgery International (PSI) ─────────────────────────────────
    # Journal international à dominante européenne. Méta-analyses multicentriques
    # sur malformations congénitales, laparoscopie pédiatrique, chirurgie néonatale.
    # Publie régulièrement les positions de l'EUPSA et de l'ESPES.
    {
        "source": "pubmed_psi",
        "journal_term": f'"Pediatr Surg Int"[Journal] AND {_PT_OR_TITLE}',
        "label": "Pediatric Surgery International (PSI) — EUPSA/ESPES",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 6,
    },

    # ── European Journal of Pediatric Surgery (EJPS) ──────────────────────────
    # Organe officiel de l'EUPSA (European Paediatric Surgeons' Association).
    # Focus chirurgie néonatale (atrésie œsophagienne, hernie diaphragmatique),
    # oncologie pédiatrique chirurgicale, urologie pédiatrique (hypospadias,
    # cryptorchidie, reflux), laparoscopie pédiatrique européenne.
    {
        "source": "pubmed_ejps",
        "journal_term": f'"Eur J Pediatr Surg"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Journal of Pediatric Surgery (EJPS/EUPSA)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 6,
    },

    # ── Seminars in Pediatric Surgery — revues thématiques et guidelines ───────
    # Chaque numéro est dédié à un thème clinique (brûlures pédiatriques,
    # atrésie biliaire, oncologie chirurgicale, chirurgie minimalemente invasive).
    # Filtre titre : ne capture que les guidelines, consensus et revues systématiques.
    {
        "source": "pubmed_semin_pediatr_surg",
        "journal_term": (
            '"Semin Pediatr Surg"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "expert opinion"[Title] OR '
            '"clinical practice"[Title] OR "systematic review"[Title] OR '
            '"meta-analysis"[Title]'
            ')'
        ),
        "label": "Seminars in Pediatric Surgery — Guidelines et consensus IPEG/APSA",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 5,
    },

    # ── JPS Guidelines — IPEG/APSA/EUPSA recommendations ─────────────────────
    # Filtre sur Practice Guideline[pt] + titres de guidelines pour extraire
    # uniquement les recommandations de sociétés savantes publiées dans JPS.
    # Complémentaire de pubmed_jps : capte les guidelines non tagguées PT_FILTER.
    {
        "source": "pubmed_jps_guidelines",
        "journal_term": (
            '"J Pediatr Surg"[Journal] AND ('
            '"Practice Guideline"[pt] OR '
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "clinical practice guideline"[Title] OR '
            '"best practice"[Title]'
            ')'
        ),
        "label": "JPS Guidelines — Recommandations IPEG/APSA/EUPSA publiées dans JPS",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 5,
    },

    # ── Journal of Pediatric Urology (JPU) — EAU/ESPU ────────────────────────
    # Journal officiel de l'ESPU (European Society for Paediatric Urology) et
    # de la WFPU. Publie les guidelines EAU Pediatric Urology, RCTs multicentriques
    # sur hypospadias, cryptorchidie, RVU, VUP, SJPU, neurologie urinaire pédiatrique.
    # Volume élevé mais filtre PT élimine les séries rétrospectives mono-centriques.
    {
        "source": "pubmed_jpu",
        "journal_term": f'"J Pediatr Urol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Pediatric Urology (JPU) — ESPU/EAU guidelines et RCTs",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 6,
    },

    # ── JPU Guidelines — EAU Pediatric / ESPU ────────────────────────────────
    # Filtre titre pour capturer les guidelines EAU Pediatric publiées dans JPU
    # (souvent non taguées Practice Guideline[pt] dans PubMed).
    {
        "source": "pubmed_jpu_guidelines",
        "journal_term": (
            '"J Pediatr Urol"[Journal] AND ('
            '"Practice Guideline"[pt] OR '
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "EAU"[Title] OR "ESPU"[Title] OR '
            '"clinical practice"[Title] OR "best practice"[Title]'
            ')'
        ),
        "label": "JPU Guidelines — EAU Pediatric Urology / ESPU recommandations",
        "source_type": "recommandation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 5,
    },

    # ── Journal of Pediatric Gastroenterology & Nutrition (JPGN) ─────────────
    # Organe officiel de l'ESPGHAN et de la NASPGHAN. Publie les guidelines
    # conjointes sur nutrition entérale/parentérale pédiatrique, maladies
    # inflammatoires chroniques intestinales, atrésie biliaire, cholestase
    # néonatale. Pertinent pour le chirurgien pédiatrique (Kasai, MICI chirurgicale,
    # stomies pédiatriques). Filtre PT élimine lettres et séries rétrospectives.
    {
        "source": "pubmed_jpgn",
        "journal_term": f'"J Pediatr Gastroenterol Nutr"[Journal] AND {_PT_FILTER}',
        "label": "JPGN — ESPGHAN/NASPGHAN guidelines & RCTs gastro-chirurgie pédiatrique",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 6,
    },

    # ── Annals of Surgery — articles pédiatriques ────────────────────────────
    # Journal généraliste de chirurgie à fort impact. Publie les grands RCTs
    # multicentriques et méta-analyses de chirurgie pédiatrique lorsque l'effectif
    # ou l'impact justifie une publication hors journaux spécialisés.
    # Filtre titre "pediatric/paediatric/neonatal/congenital" + PT pour limiter
    # le bruit des articles adultes.
    {
        "source": "pubmed_ann_surg_pediatric",
        "journal_term": (
            '"Ann Surg"[Journal] AND '
            '(pediatric[Title] OR paediatric[Title] OR neonatal[Title] OR '
            'congenital[Title] OR "pediatric surgery"[Title] OR '
            '"children"[Title] OR infant[Title]) AND '
            f'{_PT_FILTER}'
        ),
        "label": "Annals of Surgery — chirurgie pédiatrique (RCTs & méta-analyses)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 7,
    },

    # ── World Journal of Surgery — section pédiatrique ───────────────────────
    # Journal de l'ISS/SIC. Publie des études multicentriques internationales
    # en chirurgie pédiatrique, notamment sur les traumatismes pédiatriques,
    # l'appendicite, les malformations congénitales dans les pays à revenus
    # intermédiaires. Filtre titre pédiatrique + PT.
    {
        "source": "pubmed_wjs_pediatric",
        "journal_term": (
            '"World J Surg"[Journal] AND '
            '(pediatric[Title] OR paediatric[Title] OR neonatal[Title] OR '
            'congenital[Title] OR children[Title] OR infant[Title]) AND '
            f'{_PT_FILTER}'
        ),
        "label": "World Journal of Surgery — section pédiatrique (ISS multicenter)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 6,
    },

    # ── Journal of Laparoendoscopic & Advanced Surgical Techniques — péd ─────
    # Journal dédié aux techniques mini-invasives. Pertinent pour la laparoscopie
    # pédiatrique (appendicite, hernie, fundoplicature, pylorotomie) et les
    # nouvelles techniques endoscopiques. Filtre titre pédiatrique + PT.
    {
        "source": "pubmed_jlast_pediatric",
        "journal_term": (
            '"J Laparoendosc Adv Surg Tech A"[Journal] AND '
            '(pediatric[Title] OR paediatric[Title] OR neonatal[Title] OR '
            'children[Title] OR infant[Title]) AND '
            f'{_PT_FILTER}'
        ),
        "label": "JLAST — Laparoscopie et techniques mini-invasives pédiatriques",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-pediatrique",
        "min_score_hint": 5,
    },

    # ════════════════════════════════════════════════════════════════════════
    # PÉDIATRIE GÉNÉRALE
    # ════════════════════════════════════════════════════════════════════════

    # ── Pediatrics (AAP) ─────────────────────────────────────────────────────
    # Journal phare de l'American Academy of Pediatrics. Publie les grandes
    # études de cohorte, RCTs et guidelines AAP sur toutes les pathologies
    # de l'enfant (0-18 ans). Très bien indexé → PT_FILTER efficace.
    {
        "source": "pubmed_pediatrics",
        "journal_term": f'"Pediatrics"[Journal] AND {_PT_FILTER}',
        "label": "Pediatrics (AAP) — RCTs, cohortes et guidelines pédiatrie générale",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 6,
    },

    # ── Pediatrics — AAP Clinical Practice Guidelines ───────────────────────
    # Filtre dédié aux Clinical Practice Guidelines et Policy Statements AAP
    # publiés dans Pediatrics. Capture les recommandations pratiques directement
    # applicables (asthme, bronchiolite, scarlatine, TDAH, fièvre, etc.).
    {
        "source": "pubmed_pediatrics_guidelines",
        "journal_term": (
            '"Pediatrics"[Journal] AND '
            '(Practice Guideline[pt] OR Guideline[pt] OR '
            '"Clinical Practice Guideline"[pt] OR '
            '"policy statement"[Title] OR "clinical report"[Title] OR '
            '"technical report"[Title])'
        ),
        "label": "Pediatrics AAP — Clinical Practice Guidelines et Policy Statements",
        "source_type": "recommandation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 7,
    },

    # ── JAMA Pediatrics ───────────────────────────────────────────────────────
    # Journal à fort impact (IF > 20). Publie les grands RCTs multicentriques,
    # méta-analyses et analyses de cohortes en pédiatrie générale et
    # néonatologie. Bien indexé → PT_FILTER efficace.
    {
        "source": "pubmed_jama_peds",
        "journal_term": f'"JAMA Pediatr"[Journal] AND {_PT_FILTER}',
        "label": "JAMA Pediatrics — grands RCTs et méta-analyses pédiatrie",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 7,
    },

    # ── Archives of Disease in Childhood ────────────────────────────────────
    # Journal européen de référence (BMJ). Couvre pédiatrie générale, néonatologie,
    # soins primaires pédiatriques. Proche de la pratique européenne/française.
    {
        "source": "pubmed_arch_dis_child",
        "journal_term": f'"Arch Dis Child"[Journal] AND {_PT_FILTER}',
        "label": "Archives of Disease in Childhood — pédiatrie générale européenne",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 6,
    },

    # ── European Journal of Pediatrics ──────────────────────────────────────
    # Journal européen (Springer). Publie RCTs et études multicentriques sur
    # pathologies communes de l'enfant. Moins bien indexé en types PubMed →
    # _PT_OR_TITLE pour capter les articles récents avant attribution des tags.
    {
        "source": "pubmed_eur_j_pediatr",
        "journal_term": f'"Eur J Pediatr"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Journal of Pediatrics — pédiatrie générale européenne",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 5,
    },

    # ── Lancet Child & Adolescent Health ────────────────────────────────────
    # Journal à très fort impact (IF ~30, Lancet group). Publie les plus grands
    # RCTs multicentriques et méta-analyses en pédiatrie générale, néonatologie,
    # santé mentale, nutrition et infectiologie. Référence internationale
    # incontournable — articles systématiquement bien indexés.
    {
        "source": "pubmed_lancet_child",
        "journal_term": f'"Lancet Child Adolesc Health"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Child & Adolescent Health — grands RCTs pédiatrie (IF ~30)",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 7,
    },

    # ── Journal of Pediatrics ────────────────────────────────────────────────
    # Journal nord-américain de référence (Elsevier, fondé 1932). Publie RCTs,
    # méta-analyses et éditoriaux en pédiatrie générale, néonatologie et
    # maladies chroniques pédiatriques. Filtre PT_OR_TITLE pour compenser
    # l'indexation PT variable des articles récents.
    {
        "source": "pubmed_j_pediatr",
        "journal_term": f'"J Pediatr"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Pediatrics — RCTs et cohortes pédiatrie nord-américaine",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 6,
    },

    # ── Archives de Pédiatrie ────────────────────────────────────────────────
    # Journal officiel de la Société Française de Pédiatrie (SFP, Elsevier).
    # Publie en français : recommandations nationales SFP, mises au point,
    # épidémiologie française, pratiques pédiatriques en contexte FR/EU.
    # Filtre titre car indexation PubMed PT partielle (journal partiellement
    # anglophone depuis 2022).
    {
        "source": "pubmed_arch_pediatr",
        "journal_term": f'"Arch Pediatr"[Journal] AND {_PT_OR_TITLE}',
        "label": "Archives de Pédiatrie — recommandations SFP et épidémiologie française",
        "source_type": "recommandation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 6,
    },

    # ── Pediatric Infectious Disease Journal (PIDJ) ──────────────────────────
    # Journal de référence mondiale en infectiologie pédiatrique (Wolters Kluwer).
    # Publie RCTs sur antibiotiques, vaccins, infections respiratoires, méningites,
    # infections urinaires et ORL. Bien indexé PubMed — PT_FILTER efficace.
    {
        "source": "pubmed_pidj",
        "journal_term": f'"Pediatr Infect Dis J"[Journal] AND {_PT_FILTER}',
        "label": "PIDJ — RCTs et méta-analyses en infectiologie pédiatrique",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 6,
    },

    # ── Acta Paediatrica ─────────────────────────────────────────────────────
    # Journal européen de référence (Wiley, groupe Nordique). Publie les données
    # épidémiologiques scandinaves, RCTs en néonatologie, nutrition pédiatrique
    # et développement de l'enfant. Proxy pratiques européennes continentales.
    # Filtre titre pour compenser l'indexation PT variable.
    {
        "source": "pubmed_acta_paediatr",
        "journal_term": f'"Acta Paediatr"[Journal] AND {_PT_OR_TITLE}',
        "label": "Acta Paediatrica — pédiatrie générale européenne (Nordic)",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 5,
    },

    # ── Pediatric Neurology ──────────────────────────────────────────────────
    # Journal de référence en neurologie pédiatrique (Elsevier). Publie les
    # guidelines sur épilepsie, céphalées, troubles du développement neurologique,
    # paralysie cérébrale — sous-spécialité à fort impact sur le pédiatre généraliste
    # (épilepsie = 1ère neuro pédiatrique courante). Filtre PT_OR_TITLE.
    {
        "source": "pubmed_pediatr_neurol",
        "journal_term": f'"Pediatr Neurol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Pediatric Neurology — guidelines épilepsie et neurologie pédiatrique",
        "source_type": "innovation",
        "specialty_hint": "pediatrie",
        "min_score_hint": 6,
    },

    # ==========================================================================
    # ── ANESTHÉSIOLOGIE-RÉANIMATION ───────────────────────────────────────────
    # ==========================================================================
    # 11 journaux PubMed couvrant anesthésie péri-opératoire (AG, ALR, voies
    # aériennes, TIVA, ERAS) ET réanimation/soins intensifs chirurgicaux
    # (SDRA, choc septique, analgosédation, ventilation protectrice).
    # Complète les 2 RSS déjà actifs : ESICM (esicm.org/feed) + ESAIC (esaic.org/feed).
    # ==========================================================================

    # ── Anesthesiology (ASA flagship) ────────────────────────────────────────
    # Journal de référence mondial en anesthésiologie (American Society of
    # Anesthesiologists). IF ~8. Publie les grands RCTs péri-opératoires,
    # méta-analyses techniques anesthésiques, guidelines ASA (voies aériennes,
    # jeûne pré-opératoire, monitoring neuromusculaire, antibioprophylaxie).
    {
        "source": "pubmed_anesthesiology",
        "journal_term": f'"Anesthesiology"[Journal] AND {_PT_OR_TITLE}',
        "label": "Anesthesiology (ASA flagship) — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── British Journal of Anaesthesia (BJA) ─────────────────────────────────
    # Flagship européen (AAGBI/RCoA). IF ~8. Publie les RCTs multicentriques
    # européens : voies aériennes difficiles (DAS guidelines), décurarisation
    # (TOF ratio), TIVA vs volatils, ALR écho-guidé, pharmacologie anesthésique.
    {
        "source": "pubmed_bja",
        "journal_term": f'"Br J Anaesth"[Journal] AND {_PT_OR_TITLE}',
        "label": "British Journal of Anaesthesia (BJA) — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── Anesthesia & Analgesia (IARS) ────────────────────────────────────────
    # Journal à fort volume (IARS — Wolters Kluwer). IF ~5. Publie RCTs sur
    # pharmacologie anesthésique, analgésie multimodale, ERAS, techniques ALR,
    # monitoring hémodynamique. Grand volume → filtre PT strict, seuil 6.
    {
        "source": "pubmed_anesth_analg",
        "journal_term": f'"Anesth Analg"[Journal] AND {_PT_OR_TITLE}',
        "label": "Anesthesia & Analgesia (IARS) — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── Anaesthesia (AAGBI) ───────────────────────────────────────────────────
    # Journal de l'Association of Anaesthetists GB & Ireland (Wiley). IF ~10.
    # Publie les guidelines DAS (Difficult Airway Society) sur voies aériennes,
    # RCTs de haute qualité, méta-analyses ALR, pharmacovigilance anesthésique.
    # Complémentaire de BJA pour la couverture UK/EU.
    {
        "source": "pubmed_anaesthesia",
        "journal_term": f'"Anaesthesia"[Journal] AND {_PT_OR_TITLE}',
        "label": "Anaesthesia (AAGBI — Association of Anaesthetists GB&I)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── European Journal of Anaesthesiology (EJA) ────────────────────────────
    # Journal officiel de l'ESAIC (European Society of Anaesthesiology and
    # Intensive Care). IF ~6. Publie les guidelines ESAIC, RCTs multicentriques
    # européens, études sur ERAS, monitoring intraopératoire, ALR écho-guidé.
    {
        "source": "pubmed_eja",
        "journal_term": f'"Eur J Anaesthesiol"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Journal of Anaesthesiology (EJA — ESAIC)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── Anaesthesia Critical Care & Pain Medicine (ex-AFAR, SFAR) ───────────
    # Journal officiel de la SFAR (Société Française d'Anesthésie-Réanimation).
    # Publie les recommandations formalisées d'experts SFAR (RFE), consensus
    # français sur voies aériennes, gestion péri-opératoire, réanimation.
    # Indexation PubMed partielle → _PT_OR_TITLE pour ne pas rater les RFE récentes.
    {
        "source": "pubmed_accpm",
        "journal_term": f'"Anaesth Crit Care Pain Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Anaesth Crit Care Pain Med (ex-AFAR, SFAR officiel) — RFE & RCTs",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── SFAR Guidelines — filtre titre recommandation dans ACCPM ─────────────
    # Les Recommandations Formalisées d'Experts (RFE) SFAR sont publiées dans ACCPM.
    # Filtre titre pour les capturer même sans tag Practice Guideline[pt].
    {
        "source": "pubmed_sfar_guidelines",
        "journal_term": (
            '"Anaesth Crit Care Pain Med"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "SFAR"[Title] OR '
            '"expert consensus"[Title] OR "clinical practice"[Title] OR '
            '"formalized expert recommendations"[Title] OR "RFE"[Title]'
            ')'
        ),
        "label": "SFAR Guidelines (RFE) — Anaesth Crit Care Pain Med",
        "source_type": "recommandation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 4,
    },

    # ── Regional Anesthesia and Pain Medicine (RAPM) ─────────────────────────
    # Journal de référence mondial en anesthésie locorégionale (ASRA). IF ~8.
    # Publie les guidelines ASRA (anticoagulants et ALR, anesthésie neuraxiale),
    # RCTs blocs écho-guidés (TAP, ESP, serratus, interscalénique), méta-analyses
    # ALR vs AG, complications neurologiques.
    {
        "source": "pubmed_reg_anesth",
        "journal_term": f'"Reg Anesth Pain Med"[Journal] AND {_PT_FILTER}',
        "label": "Regional Anesthesia and Pain Medicine (RAPM — ASRA)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── Intensive Care Medicine (ESICM flagship) ──────────────────────────────
    # Journal officiel de l'ESICM (European Society of Intensive Care Medicine).
    # IF ~30. Publie les guidelines Surviving Sepsis Campaign, ARDS Network
    # updates, études sur ventilation protectrice, analgosédation, nutrition ICU,
    # monitorage hémodynamique. Complémentaire du RSS ESICM déjà actif.
    {
        "source": "pubmed_intensive_care_med",
        "journal_term": f'"Intensive Care Med"[Journal] AND {_PT_FILTER}',
        "label": "Intensive Care Medicine (ESICM flagship — IF ~30)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── Critical Care Medicine (SCCM) ────────────────────────────────────────
    # Journal de la Society of Critical Care Medicine (Wolters Kluwer). IF ~8.
    # Publie les grandes études RCT en réanimation : choc septique (cristalloïdes,
    # vasopresseurs), ARDS (DV, ECMO), nutrition, analgosédation (PADIS trial),
    # delirium (CAM-ICU), prévention infections nosocomiales.
    {
        "source": "pubmed_crit_care_med",
        "journal_term": f'"Crit Care Med"[Journal] AND {_PT_FILTER}',
        "label": "Critical Care Medicine (SCCM flagship)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── Critical Care (BioMed Central) ───────────────────────────────────────
    # Journal open-access à fort IF (~15). Publie les méta-analyses en réseau
    # (NMA) sur vasopresseurs, sédatifs, modes ventilatoires, grandes études
    # observationnelles multicentriques ICU, études de simulation.
    {
        "source": "pubmed_crit_care",
        "journal_term": f'"Crit Care"[Journal] AND {_PT_FILTER}',
        "label": "Critical Care — BioMed Central (IF ~15)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 6,
    },

    # ── Journal of Cardiothoracic and Vascular Anesthesia (JCVA) ─────────────
    # Journal de référence en anesthésie cardio-thoracique et vasculaire
    # (Elsevier — SOCCA). IF ~5. Publie les RCTs sur anesthésie TAVI, chirurgie
    # cardiaque sous CEC, anesthésie vasculaire, monitoring cardiaque peropératoire
    # (ETO, Swan-Ganz), gestion hémodynamique. Complémentaire de JTCVS.
    {
        "source": "pubmed_jcva",
        "journal_term": f'"J Cardiothorac Vasc Anesth"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Cardiothoracic and Vascular Anesthesia (JCVA — SOCCA)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── Acta Anaesthesiologica Scandinavica (Wiley — SSAI) ────────────────────
    # Journal officiel de la Scandinavian Society of Anaesthesiology and
    # Intensive Care Medicine. IF ~4. Publie les RCTs multicentriques nordiques,
    # méta-analyses sur protocoles ERAS, gestion douleur postopératoire (bloc
    # TAP/ESP), sédation ICU, complications respiratoires péri-opératoires.
    {
        "source": "pubmed_acta_anaesthesiol_scand",
        "journal_term": f'"Acta Anaesthesiol Scand"[Journal] AND {_PT_OR_TITLE}',
        "label": "Acta Anaesthesiologica Scandinavica (SSAI — Wiley)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── Canadian Journal of Anesthesia (CJA — CAS) ───────────────────────────
    # Journal officiel de la Canadian Anesthesiologists' Society (Springer).
    # IF ~4. Publie les guidelines CAS (voies aériennes difficiles, anesthésie
    # obstétricale, monitored anesthesia care), RCTs sur blocs régionaux,
    # simulation en anesthésie, pharmacocinétique agents anesthésiques.
    {
        "source": "pubmed_can_j_anaesth",
        "journal_term": f'"Can J Anaesth"[Journal] AND {_PT_OR_TITLE}',
        "label": "Canadian Journal of Anesthesia (CJA — CAS)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── PAIN (IASP flagship) ───────────────────────────────────────────────────
    # Journal officiel de l'International Association for the Study of Pain.
    # IF ~7. Publie les RCTs sur douleur chronique (douleur neuropathique,
    # fibromyalgie, douleur cancéreuse), blocs interventionnels (radio-fréquence,
    # neurostimulation), guidelines IASP sur opioïdes, méta-analyses traitements
    # multimodaux. Incontournable pour la médecine de la douleur.
    {
        "source": "pubmed_pain_iasp",
        "journal_term": f'"Pain"[Journal] AND {_PT_OR_TITLE}',
        "label": "PAIN (IASP flagship — IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── Journal of Pain Research (Dove Medical Press) ─────────────────────────
    # Journal open-access à fort volume (Dove Press). Publie les études sur
    # techniques interventionnelles de la douleur (blocs écho-guidés, pompes
    # intrathécales, spinal cord stimulation), pharmacologie analgésiques
    # (kétamine, lidocaïne IV, dexaméthasone), ERAS et douleur postopératoire.
    # _PT_OR_TITLE pour capter les études récentes non encore taguées.
    {
        "source": "pubmed_j_pain_res",
        "journal_term": f'"J Pain Res"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Pain Research (Dove Medical Press — open access)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ── Paediatric Anaesthesia (Wiley — APAGBI) ──────────────────────────────
    # Journal officiel de l'Association of Paediatric Anaesthetists of Great
    # Britain and Ireland (Wiley). IF ~3. Publie les RCTs et recommandations sur
    # anesthésie pédiatrique : voies aériennes enfant (masque laryngé taille),
    # analgésie postopératoire (caudal, bloc TAP), induction inhalatoire vs IV,
    # prémédication, gestion douleur nouveau-né. Complémentaire de Paediatric
    # Anaesthesia guidelines ESAIC.
    {
        "source": "pubmed_paediatr_anaesth",
        "journal_term": f'"Paediatr Anaesth"[Journal] AND {_PT_OR_TITLE}',
        "label": "Paediatric Anaesthesia (APAGBI — Wiley)",
        "source_type": "innovation",
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 5,
    },

    # ==========================================================================
    # ── BIOLOGIE MÉDICALE ─────────────────────────────────────────────────────
    # ==========================================================================
    # 10 journaux PubMed couvrant l'ensemble du champ du biologiste médical :
    # biochimie clinique, hématologie de laboratoire, microbiologie (bactério,
    # virologie, mycologie), biologie moléculaire/NGS, transfusion, pathologie.
    # Complète le scraping EFLM déjà actif (eflm.eu → eflm_guidelines).
    # ==========================================================================

    # ── Clinical Chemistry (AACC flagship) ───────────────────────────────────
    # THE journal de référence mondial en biologie clinique (IF ~14). Publie les
    # grandes études de validation analytique, nouveaux algorithmes diagnostiques
    # (hs-troponine 0h/1h, D-dimères), nouvelles techniques (LC-MS/MS, mNGS),
    # guidelines AACC sur interprétation et seuils décisionnels.
    {
        "source": "pubmed_clin_chem",
        "journal_term": f'"Clin Chem"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Chemistry (AACC flagship — IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 6,
    },

    # ── Clinical Chemistry and Laboratory Medicine (CCLM — EFLM) ─────────────
    # Journal officiel de l'EFLM (European Federation of Clinical Chemistry and
    # Laboratory Medicine). IF ~6. Publie les recommandations EFLM sur les
    # spécifications analytiques (APS), valeurs de référence, pré-analytique,
    # EEQ, accréditation ISO 15189. THE référence européenne pour les biologistes.
    {
        "source": "pubmed_cclm",
        "journal_term": f'"Clin Chem Lab Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Clinical Chemistry and Laboratory Medicine (CCLM — EFLM)",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 5,
    },

    # ── CCLM — EFLM Guidelines uniquement ────────────────────────────────────
    # Filtre titre pour capturer les recommandations EFLM publiées dans CCLM
    # (spécifications analytiques, pre-analytique, valeurs de référence).
    {
        "source": "pubmed_eflm_guidelines_cclm",
        "journal_term": (
            '"Clin Chem Lab Med"[Journal] AND ('
            'guideline[Title] OR recommendation[Title] OR consensus[Title] OR '
            '"position statement"[Title] OR "EFLM"[Title] OR '
            '"analytical performance"[Title] OR "reference interval"[Title] OR '
            '"biological variation"[Title] OR "allowable"[Title] OR '
            '"pre-analytical"[Title] OR "quality specification"[Title]'
            ')'
        ),
        "label": "CCLM — Recommandations EFLM (APS, pré-analytique, valeurs ref.)",
        "source_type": "recommandation",
        "specialty_hint": "biologiste",
        "min_score_hint": 4,
    },

    # ── Journal of Clinical Microbiology (JCM — ASM) ──────────────────────────
    # Journal de référence en microbiologie clinique (American Society for
    # Microbiology). IF ~9. Publie les études de performance des nouvelles
    # méthodes diagnostiques (PCR multiplexe, MALDI-TOF, mNGS), détections de
    # nouvelles résistances (carbapénémases, Candida auris), recommandations ASM.
    {
        "source": "pubmed_jcm",
        "journal_term": f'"J Clin Microbiol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Clinical Microbiology (JCM — ASM, IF ~9)",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 6,
    },

    # ── Clinical Microbiology and Infection (CMI — ESCMID) ───────────────────
    # Journal officiel de l'ESCMID. IF ~14. Publie les guidelines ESCMID sur
    # l'antibiothérapie, les diagnostics microbiologiques (breakpoints EUCAST),
    # les BMR/BHR émergentes, les nouvelles méthodes de diagnostic rapide.
    {
        "source": "pubmed_cmi",
        "journal_term": f'"Clin Microbiol Infect"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Microbiology and Infection (CMI — ESCMID, IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 6,
    },

    # ── Annals of Clinical Biochemistry ──────────────────────────────────────
    # Journal de référence UK/EU en biochimie clinique (SAGE). Publie les études
    # de validation de nouveaux marqueurs (troponine, NTproBNP, cystatine C),
    # interférences analytiques, recommandations ACB et RCPA.
    {
        "source": "pubmed_ann_clin_biochem",
        "journal_term": f'"Ann Clin Biochem"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals of Clinical Biochemistry — biochimie clinique UK/EU",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 5,
    },

    # ── American Journal of Clinical Pathology (AJCP) ────────────────────────
    # Journal de pathologie clinique de l'ASCP (American Society for Clinical
    # Pathology). IF ~4. Publie des études multicentriques sur les performances
    # diagnostiques, les algorithmes interprétatifs, les nouvelles techniques
    # histologiques et moléculaires en anatomopathologie et biologie médicale.
    {
        "source": "pubmed_ajcp",
        "journal_term": f'"Am J Clin Pathol"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Clinical Pathology (AJCP — ASCP)",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 6,
    },

    # ── Journal of Molecular Diagnostics (JMD) ───────────────────────────────
    # Journal de référence en diagnostic moléculaire (Association for Molecular
    # Pathology — AMP). IF ~6. Publie les études de validation des panels NGS
    # en oncologie, des PCR diagnostiques, du séquençage métagénomique clinique
    # (mNGS), des tests de biopsie liquide (ctDNA) et des FISH panels.
    {
        "source": "pubmed_j_mol_diagn",
        "journal_term": f'"J Mol Diagn"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Molecular Diagnostics (JMD — AMP)",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 6,
    },

    # ── Transfusion (AABB) ────────────────────────────────────────────────────
    # Journal de référence en médecine transfusionnelle (AABB). IF ~4. Publie
    # les études sur les produits sanguins labiles (PSL), les protocoles de
    # transfusion (seuil d'Hb, PFC, plaquettes), les nouvelles techniques
    # immuno-hématologiques (RAI, groupage), les recommandations SFTS/AABB.
    {
        "source": "pubmed_transfusion",
        "journal_term": f'"Transfusion"[Journal] AND {_PT_FILTER}',
        "label": "Transfusion (AABB) — immuno-hématologie et produits sanguins",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 6,
    },

    # ── Vox Sanguinis (ISBT) ─────────────────────────────────────────────────
    # Journal de l'International Society of Blood Transfusion (Wiley). IF ~3.
    # Publie les recommandations ISBT sur la transfusion, les études de
    # sécurité des PSL, les nouvelles techniques de groupage et RAI, les
    # risques infectieux transfusionnels (hémovigilance).
    {
        "source": "pubmed_vox_sanguinis",
        "journal_term": f'"Vox Sang"[Journal] AND {_PT_OR_TITLE}',
        "label": "Vox Sanguinis (ISBT) — transfusion et hémovigilance",
        "source_type": "innovation",
        "specialty_hint": "biologiste",
        "min_score_hint": 5,
    },

    # ==========================================================================
    # ── CARDIOLOGIE ───────────────────────────────────────────────────────────
    # ==========================================================================
    # 10 journaux PubMed couvrant la cardiologie MÉDICALE (distincts des journaux
    # chirurgicaux déjà configurés pour chirurgie-cardiaque : JTCVS, EJCTS, Ann
    # Thorac Surg). Couvre IC, FA/rythmologie, SCA/coronarographie, prévention CV,
    # valvulopathies médicales, HTAP, cardio-oncologie.
    # Complète le scraping ESC guidelines déjà actif (esc_guidelines).
    # ==========================================================================

    # ── European Heart Journal — cardiologie médicale ─────────────────────────
    # Journal phare de l'ESC (IF ~39). Publie toutes les grandes études ESC
    # en cardiologie médicale : IC, FA, SCA, prévention, dyslipidémies, HTAP.
    # Note : une entrée séparée existe pour chirurgie-cardiaque (pubmed_eur_heart_j)
    # avec filtre chirurgical. Ici : filtre médical cardiologique (hors chir).
    {
        "source": "pubmed_ehj_cardio",
        "journal_term": (
            '"Eur Heart J"[Journal] AND ('
            '"heart failure"[tiab] OR "atrial fibrillation"[tiab] OR '
            '"coronary artery disease"[tiab] OR "myocardial infarction"[tiab] OR '
            '"acute coronary syndrome"[tiab] OR "percutaneous coronary"[tiab] OR '
            '"cardiomyopathy"[tiab] OR "hypertrophic cardiomyopathy"[tiab] OR '
            '"pulmonary hypertension"[tiab] OR "cardiac amyloidosis"[tiab] OR '
            '"dyslipidemia"[tiab] OR "lipid-lowering"[tiab] OR '
            '"anticoagulat"[tiab] OR "arrhythmia"[tiab] OR '
            '"catheter ablation"[tiab] OR "implantable defibrillator"[tiab] OR '
            '"pacemaker"[tiab] OR "cardiac resynchronization"[tiab]'
            f') AND {_PT_FILTER}'
        ),
        "label": "European Heart Journal — cardiologie médicale (IC, FA, SCA, prévention)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 7,
    },

    # ── European Journal of Heart Failure (EJHF — HFA/ESC) ───────────────────
    # Journal officiel de la Heart Failure Association (HFA) de l'ESC. IF ~18.
    # 100 % dédié à l'insuffisance cardiaque : RCTs thérapeutiques (iSGLT2,
    # ARNi, vericiguat), stratégies de titration, biomarqueurs (NT-proBNP guided),
    # réadaptation cardiaque, IC aiguë, gestion multidisciplinaire.
    {
        "source": "pubmed_ejhf",
        "journal_term": f'"Eur J Heart Fail"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Journal of Heart Failure (EJHF — HFA/ESC, IF ~18)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── JACC — cardiologie médicale ───────────────────────────────────────────
    # Journal of the American College of Cardiology (IF ~24). Filtre médical :
    # IC, FA, prévention, SCA/PCI, HTAP, cardiomyopathies — exclut chir cardiaque
    # déjà capturé dans pubmed_jacc_card.
    {
        "source": "pubmed_jacc_medical",
        "journal_term": (
            '"J Am Coll Cardiol"[Journal] AND ('
            '"heart failure"[tiab] OR "atrial fibrillation"[tiab] OR '
            '"percutaneous coronary intervention"[tiab] OR "PCI"[tiab] OR '
            '"acute coronary syndrome"[tiab] OR "myocardial infarction"[tiab] OR '
            '"cardiomyopathy"[tiab] OR "pulmonary hypertension"[tiab] OR '
            '"dyslipidemia"[tiab] OR "statin"[tiab] OR "PCSK9"[tiab] OR '
            '"catheter ablation"[tiab] OR "implantable"[tiab] OR '
            '"prevention"[tiab] OR "antithrombotic"[tiab] OR "anticoagul"[tiab]'
            f') AND {_PT_FILTER}'
        ),
        "label": "JACC — cardiologie médicale (IC, FA, SCA/PCI, prévention, HTAP)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 7,
    },

    # ── JACC: Heart Failure ───────────────────────────────────────────────────
    # Sous-journal JACC 100 % dédié à l'insuffisance cardiaque. IF ~14.
    # Publie les grands RCTs IC (EMPEROR, DELIVER extensions), les études de
    # titration, les biomarqueurs, les protocoles de réhabilitation cardiaque.
    {
        "source": "pubmed_jacc_hf",
        "journal_term": f'"JACC Heart Fail"[Journal] AND {_PT_OR_TITLE}',
        "label": "JACC: Heart Failure — insuffisance cardiaque dédiée (IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── JACC: Clinical Electrophysiology ─────────────────────────────────────
    # Sous-journal JACC dédié à la rythmologie et l'électrophysiologie. IF ~9.
    # Publie les résultats d'ablation (FA, TV, ESV), les études sur PM/DAI/CRT,
    # les nouvelles technologies (PFA, mapping 3D, S-ICD, Micra), les guidelines
    # HRS/EHRA sur les arythmies.
    {
        "source": "pubmed_jacc_ep",
        "journal_term": f'"JACC Clin Electrophysiol"[Journal] AND {_PT_OR_TITLE}',
        "label": "JACC: Clinical Electrophysiology — ablation, PM/DAI, arythmies",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── Heart Rhythm (HRS) ────────────────────────────────────────────────────
    # Journal officiel de la Heart Rhythm Society (HRS). IF ~6. Publie les
    # guidelines HRS sur la FA, les arythmies ventriculaires, les syncopes,
    # les dispositifs implantables, les nouvelles techniques d'ablation (PFA).
    {
        "source": "pubmed_heart_rhythm",
        "journal_term": f'"Heart Rhythm"[Journal] AND {_PT_OR_TITLE}',
        "label": "Heart Rhythm (HRS flagship) — arythmies et dispositifs implantables",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── Europace (EHRA/ESC) ───────────────────────────────────────────────────
    # Journal officiel de l'EHRA (European Heart Rhythm Association). IF ~7.
    # Publie les guidelines EHRA sur la FA (anticoagulation, cardioversion,
    # ablation), les arythmies héréditaires (Brugada, QT long), les dispositifs
    # implantables en Europe, les registres européens de rythmologie.
    {
        "source": "pubmed_europace",
        "journal_term": f'"Europace"[Journal] AND {_PT_OR_TITLE}',
        "label": "Europace (EHRA/ESC) — FA, arythmies, dispositifs, guidelines EHRA",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── Archives of Cardiovascular Diseases (ACVD — SFC) ─────────────────────
    # Journal officiel de la Société Française de Cardiologie (SFC). Publie les
    # recommandations et positions françaises, les registres nationaux (FAST-MI,
    # OFRECE), les études multicentriques en contexte français/européen.
    # Filtre PT_OR_TITLE : indexation PubMed partielle pour les recommandations SFC.
    {
        "source": "pubmed_acvd",
        "journal_term": f'"Arch Cardiovasc Dis"[Journal] AND {_PT_OR_TITLE}',
        "label": "Archives of Cardiovascular Diseases (ACVD — SFC)",
        "source_type": "recommandation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 5,
    },

    # ── ESC Guidelines — cardiologie médicale (via EHJ + Eur J Heart Fail) ───
    # Filtre titre sur les guidelines ESC publiées dans EHJ et EJHF.
    # Distinct de pubmed_esc_guidelines (mappé sur chirurgie-cardiaque) :
    # ici capte les guidelines cardio médicales (IC, FA, SCA, prévention, HTAP).
    {
        "source": "pubmed_esc_guidelines_cardio",
        "journal_term": (
            '("Eur Heart J"[Journal] OR "Eur J Heart Fail"[Journal] OR '
            '"Eur Heart J Cardiovasc Pharmacother"[Journal] OR '
            '"Eur Heart J Acute Cardiovasc Care"[Journal]) AND '
            '(guideline[Title] OR "ESC Guidelines"[Title] OR '
            '"consensus document"[Title] OR "position statement"[Title] OR '
            '"expert consensus"[Title] OR "recommendations for"[Title] OR '
            '"management of"[Title])'
        ),
        "label": "ESC Guidelines — cardiologie médicale (EHJ / EJHF / EHJ Pharmacother)",
        "source_type": "recommandation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 4,
    },

    # ── European Heart Journal — Cardiovascular Pharmacotherapy ──────────────
    # Sous-journal ESC dédié à la pharmacologie cardiovasculaire. IF ~7.
    # Publie les études sur les nouvelles molécules CV (iSGLT2, GLP-1, PCSK9i,
    # inclisiran), les interactions médicamenteuses, la pharmacovigilance CV,
    # les essais de phase III en cardiologie médicale.
    {
        "source": "pubmed_ehj_pharmacother",
        "journal_term": f'"Eur Heart J Cardiovasc Pharmacother"[Journal] AND {_PT_FILTER}',
        "label": "EHJ Cardiovascular Pharmacotherapy — pharmacologie CV, iSGLT2, PCSK9i",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── JACC: Cardiovascular Interventions ───────────────────────────────────
    # Sous-journal JACC dédié à la cardiologie interventionnelle. IF ~12.
    # Publie les RCTs sur PCI (OCT-guidé, calcifications, bifurcations, tronc
    # commun), TAVI, LAAC, MitraClip, TEER tricuspide, fermeture FOP/CIA.
    {
        "source": "pubmed_jacc_intv",
        "journal_term": f'"JACC Cardiovasc Interv"[Journal] AND {_PT_OR_TITLE}',
        "label": "JACC: Cardiovascular Interventions — PCI, TAVI, LAAC, TEER (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── EuroIntervention (EAPCI/ESC) ─────────────────────────────────────────
    # Journal officiel de l'EAPCI (European Association of Percutaneous
    # Cardiovascular Interventions). IF ~7. Publie les études européennes sur
    # PCI complexe, TAVI (registres FRANCE-TAVI, PARTNER Europe), imagerie
    # intracoronaire (OCT, IVUS), protection cérébrale péri-TAVI.
    {
        "source": "pubmed_eurointervention",
        "journal_term": f'"EuroIntervention"[Journal] AND {_PT_OR_TITLE}',
        "label": "EuroIntervention (EAPCI/ESC) — PCI, TAVI, registres européens (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── Circulation: Cardiovascular Interventions (AHA) ──────────────────────
    # Sous-journal Circulation dédié à l'interventionnel. IF ~8. Publie les
    # RCTs AHA sur PCI haute complexité (CTO, tronc commun, choc), TAVI,
    # assistance ventriculaire (LVAD, Impella), cardiologie structurelle.
    {
        "source": "pubmed_circ_cardiovasc_intv",
        "journal_term": f'"Circ Cardiovasc Interv"[Journal] AND {_PT_OR_TITLE}',
        "label": "Circulation: Cardiovascular Interventions — PCI complexe, TAVI, LVAD (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ── JACC: Cardiovascular Imaging ─────────────────────────────────────────
    # Sous-journal JACC dédié à l'imagerie cardiaque. IF ~14. Publie les études
    # sur échocardiographie (stress, 3D, strain), CMR (LGE, T1 mapping),
    # scanner coronaire (CCTA, calcium score), imagerie nucléaire (PET-TEP).
    # Indispensable pour cardiopathies structurelles et ATTR-CM.
    {
        "source": "pubmed_jacc_img",
        "journal_term": f'"JACC Cardiovasc Imaging"[Journal] AND {_PT_OR_TITLE}',
        "label": "JACC: Cardiovascular Imaging — écho, CMR, CCTA, imagerie nucléaire (IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "cardiologie",
        "min_score_hint": 6,
    },

    # ==========================================================================
    # ── DERMATOLOGIE ──────────────────────────────────────────────────────────
    # ==========================================================================
    # 16 journaux couvrant : dermatologie inflammatoire (psoriasis, DA, pemphigus,
    # HS, GPP), dermato-oncologie (mélanome, CBC, CE cutané, CTCL), dermatologie
    # infectieuse, acnéologie, dermato-pédiatrique, réglementaire (remboursement
    # biologiques, PPP). L'EADV RSS (eadv) est déjà actif avec
    # specialty_hint="dermatologie" — ces sources PubMed complètent la couverture
    # des journaux académiques.
    # ==========================================================================

    # ── JAAD — Journal of the American Academy of Dermatology ────────────────
    # IF ~14 — flagship de l'AAD. Publie les guidelines AAD, les grandes études
    # de phase 3 sur biologiques (psoriasis, DA, mélanome), les méta-analyses
    # sur traitements systémiques. THE référence clinique nord-américaine.
    {
        "source": "pubmed_jaad",
        "journal_term": f'"J Am Acad Dermatol"[Journal] AND {_PT_FILTER}',
        "label": "JAAD — Journal of the American Academy of Dermatology (IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── BJD — British Journal of Dermatology ─────────────────────────────────
    # IF ~11 — flagship de la BAD. Publie les essais phase 3 européens,
    # les méta-analyses en réseau (NMA) sur biologiques, les guidelines BAD.
    # Forte couverture dermatologie inflammatoire et dermato-oncologie EU.
    {
        "source": "pubmed_bjd",
        "journal_term": f'"Br J Dermatol"[Journal] AND {_PT_FILTER}',
        "label": "British Journal of Dermatology (BJD) — IF ~11",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── JEADV — Journal of the European Academy of Dermatology and Venereology ─
    # IF ~6 — journal officiel EADV. Publie les guidelines EADV (psoriasis,
    # DA, acné, mélanome, infections cutanées IST), essais multicentriques EU,
    # recommandations sur thérapeutiques biologiques en contexte européen.
    # _PT_OR_TITLE pour capter les guidelines et consensus non encore typés.
    {
        "source": "pubmed_jeadv",
        "journal_term": f'"J Eur Acad Dermatol Venereol"[Journal] AND {_PT_OR_TITLE}',
        "label": "JEADV — Journal of the EADV (guidelines + essais EU, IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── European Journal of Dermatology ──────────────────────────────────────
    # IF ~3 — journal officiel du Collège Européen de Dermatologie. Publie des
    # essais cliniques multicentriques EU, guidelines de sociétés européennes
    # (EADV, EADO, GDA), études de cohorte sur biologiques en vie réelle en
    # contexte européen. Bonne pertinence pour le dermatologue praticien français.
    # NOTE : "Lancet Dermatology" non indexé MEDLINE/NLM (vérifié 2026-04-21).
    {
        "source": "pubmed_eur_j_derm",
        "journal_term": f'"Eur J Dermatol"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Dermatology — essais EU + guidelines européens (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── JAMA Dermatology ──────────────────────────────────────────────────────
    # IF ~21 — top journal AMA en dermato. Feed JAMA Dermatology déjà présent
    # dans les sources JAMA générales (jama_dermatology dans _INNOVATION_SOURCES).
    # Source PubMed dédiée ici avec filtre PT strict pour éviter les doublons
    # sur les articles non encore traités par le flux RSS général.
    {
        "source": "pubmed_jama_derm",
        "journal_term": f'"JAMA Dermatol"[Journal] AND {_PT_FILTER}',
        "label": "JAMA Dermatology — RCTs et méta-analyses (IF ~21)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── Acta Dermato-Venereologica ────────────────────────────────────────────
    # IF ~5 — journal officiel des sociétés dermatologiques scandinaves (SDS).
    # Forte couverture guidelines européennes, études observationnelles
    # multicentriques nordiques (registres), études pharmacoéconomiques sur
    # biologiques en contexte européen (données de vie réelle registres).
    # _PT_OR_TITLE pour capter les guidelines et recommandations nordiques.
    {
        "source": "pubmed_acta_derm",
        "journal_term": f'"Acta Derm Venereol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Acta Dermato-Venereologica — guidelines nordiques + essais EU (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── Dermatology (Karger / Basel) ──────────────────────────────────────────
    # IF ~4 — journal européen (Karger). Publie des études cliniques comparatives,
    # guidelines de sociétés européennes (EADO, ESMO/dermato-oncologie),
    # études de cohorte sur biologiques dermatologie. Filtre titre renforcé
    # pour compenser un IF plus modeste.
    {
        "source": "pubmed_dermatology_basel",
        "journal_term": f'"Dermatology"[Journal] AND {_PT_OR_TITLE}',
        "label": "Dermatology (Karger/Basel) — clinique + guidelines EU (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── Clinical and Experimental Dermatology ─────────────────────────────────
    # IF ~4 — journal officiel BAD/BDA. Publie des études cliniques pratiques,
    # audits de pratique, cas difficiles commentés, mises à point thérapeutiques.
    # Forte valeur pour le dermatologue praticien (moins académique que BJD).
    {
        "source": "pubmed_clin_exp_derm",
        "journal_term": f'"Clin Exp Dermatol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Clinical and Experimental Dermatology — clinique pratique BAD (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── Contact Dermatitis ────────────────────────────────────────────────────
    # IF ~4 — journal officiel ESCD (European Society of Contact Dermatitis).
    # THE référence pour la dermite de contact professionnelle et allergique :
    # nouvelles séries d'allergènes, mise à jour des batteries de patch-tests,
    # guidelines ESCD/ISCD. Impact praticien direct (patch-tests, éviction).
    {
        "source": "pubmed_contact_derm",
        "journal_term": f'"Contact Dermatitis"[Journal] AND {_PT_OR_TITLE}',
        "label": "Contact Dermatitis — ESCD, patch-tests, allergies professionnelles (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── Melanoma Research ─────────────────────────────────────────────────────
    # IF ~3 — journal dédié. Filtre renforcé sur guidelines, RCTs et méta-analyses
    # pour écarter la recherche translationnelle (biomarqueurs, modèles murins).
    # Complète Lancet Dermatology et JAAD sur le mélanome en y incluant des études
    # européennes et australiennes moins couvertes par les grands journaux.
    {
        "source": "pubmed_melanoma_res",
        "journal_term": f'"Melanoma Res"[Journal] AND {_PT_FILTER}',
        "label": "Melanoma Research — RCTs et guidelines mélanome (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── JDDG — Journal der Deutschen Dermatologischen Gesellschaft ────────────
    # IF ~3 — journal officiel de la DDG (société allemande de dermatologie).
    # Publie les guidelines DDG (souvent alignées EADV), mises à point cliniques
    # en contexte EU francophone/germanophone. Pertinent pour recommandations
    # sur biologiques, protocoles de photothérapie, dermato-infectiologie.
    # _PT_OR_TITLE indispensable : journal majoritairement position papers/guidelines.
    {
        "source": "pubmed_jddg",
        "journal_term": f'"J Dtsch Dermatol Ges"[Journal] AND {_PT_OR_TITLE}',
        "label": "JDDG — Deutsche Dermatologische Gesellschaft (guidelines EU, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── Journal of Investigative Dermatology ──────────────────────────────────
    # IF ~7 — référence pour la recherche translationnelle et mécanistique.
    # Publie aussi des RCTs et méta-analyses sur les biomarqueurs de réponse
    # aux biologiques, pharmacogénomique et essais phase 2/3. Filtre strict.
    {
        "source": "pubmed_jid",
        "journal_term": f'"J Invest Dermatol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Investigative Dermatology — essais translationnels (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 6,
    },

    # ── Dermatologic Therapy ──────────────────────────────────────────────────
    # IF ~3.5 — Wiley. Publie guidelines pratiques, revues de thérapeutique et
    # études comparatives sur traitements topiques, laser et biothérapies.
    # Filtre titre renforcé pour couvrir les guidelines sans PT strict.
    {
        "source": "pubmed_derm_therapy",
        "journal_term": f'"Dermatol Ther"[Journal] AND {_PT_OR_TITLE}',
        "label": "Dermatologic Therapy — thérapeutiques pratiques, guidelines (IF ~3.5)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── Journal of Dermatological Treatment ──────────────────────────────────
    # IF ~4 — T&F. Fort volume sur les RCTs comparatifs topiques/systémiques
    # (rétinoïdes, antibiotiques, biothérapies acnéologie/psoriasis), souvent
    # publié avant les grandes revues. Bon filet pour recommandations pratiques.
    {
        "source": "pubmed_j_derm_treat",
        "journal_term": f'"J Dermatolog Treat"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Dermatological Treatment — RCTs comparatifs (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── Pediatric Dermatology ─────────────────────────────────────────────────
    # IF ~2.5 — SDP/ESPD. Seul journal dédié à la dermato pédiatrique.
    # Couvre : DA pédiatrique (dupilumab enfant, JAKi ≥12 ans), hémangiomes
    # (propranolol), génodermatoses, mélanomes rare enfant. Filtre titre pour
    # compenser le faible IF et capter les guidelines SPD/ESPD.
    {
        "source": "pubmed_pediatr_derm",
        "journal_term": f'"Pediatr Dermatol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Pediatric Dermatology — DA enfant, hémangiomes, génodermatoses (IF ~2.5)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── International Journal of Dermatology ──────────────────────────────────
    # IF ~3.5 — ISD (International Society of Dermatology). Couverture mondiale
    # avec fort volume sur dermatologie infectieuse (lèpre, leishmaniose cutanée,
    # dermatophyties), dermatologie tropicale, et revues systématiques ISD.
    {
        "source": "pubmed_int_j_derm",
        "journal_term": f'"Int J Dermatol"[Journal] AND {_PT_OR_TITLE}',
        "label": "International Journal of Dermatology — infectieux, tropicale, ISD (IF ~3.5)",
        "source_type": "innovation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── JEADV Guidelines — guidelines EADV publiées dans JEADV ───────────────
    # Source dédiée aux guidelines/consensus/position statements EADV publiés dans
    # JEADV — séparée de pubmed_jeadv (innovation) pour éviter que les guidelines
    # ne se noient dans le flux RCT/méta-analyse. Cible : psoriasis, DA, acné,
    # mélanome, infections cutanées, GPP, hidradénite, lichen — toutes pathologies
    # pour lesquelles l'EADV publie des task-force guidelines.
    # Filtre titre centré guideline/consensus/position statement.
    {
        "source": "pubmed_jeadv_guidelines",
        "journal_term": (
            '"J Eur Acad Dermatol Venereol"[Journal] AND '
            '("guideline"[Title] OR "consensus"[Title] OR "recommendation"[Title] OR '
            '"position statement"[Title] OR "task force"[Title] OR '
            '"guideline"[pt] OR "practice guideline"[pt])'
        ),
        "label": "JEADV — Guidelines EADV (task force, consensus, position statements)",
        "source_type": "recommandation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ── Annales de Dermatologie et Vénéréologie — journal SFD ────────────────
    # IF ~3 — journal officiel de la Société Française de Dermatologie (SFD).
    # Publie les recommandations et PNDS français en dermatologie : protocoles
    # nationaux (PNDS génodermatoses, pemphigoïdes, DRESS, nécrolyse épidermique),
    # guidelines SFD (psoriasis, DA, mélanome, acné, hidradénite, lichen),
    # consensus d'experts HAS-SFD. Pertinence maximale pour la pratique française.
    # Filtre titre strict : uniquement guidelines/recommandations/PNDS/consensus.
    {
        "source": "pubmed_ann_derm_venereol",
        "journal_term": (
            '"Ann Dermatol Venereol"[Journal] AND '
            '("guideline"[Title] OR "consensus"[Title] OR "recommendation"[Title] OR '
            '"recommandation"[Title] OR "PNDS"[Title] OR "protocol"[Title] OR '
            '"position statement"[Title] OR "guideline"[pt] OR "practice guideline"[pt])'
        ),
        "label": "Annales de Dermatologie et Vénéréologie — Recommandations SFD, PNDS, consensus",
        "source_type": "recommandation",
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # ── ENDOCRINOLOGIE, DIABÉTOLOGIE, MALADIES MÉTABOLIQUES ───────────────────
    # ==========================================================================
    # 16 journaux couvrant : diabète T1/T2 (GLP-1, iSGLT2, insulines, closed-loop),
    # obésité (tirzepatide, sémaglutide 2,4 mg, chirurgie bariatrique), thyroïde
    # (cancer différencié/médullaire/anaplasique, Basedow, nodules EU-TIRADS),
    # surrénales (Cushing, Conn, phéochromocytome), hypophyse (acromégalie,
    # prolactinome, maladie de Cushing centrale), ostéoporose (romosozumab,
    # tériparatide, dénosumab), réglementaire SFE/ESE/ADA/EASD/HAS/ANSM.
    # ==========================================================================

    # ── Diabetes Care ─────────────────────────────────────────────────────────
    # IF ~16 — ADA flagship. Publie les grands RCTs sur la gestion du DT2 (EMPA-REG,
    # DECLARE, SELECT), les Standards of Care ADA annuels (guidelines de référence
    # mondiale) et les essais phase 3 (GLP-1, iSGLT2, closed-loop T1). Volume
    # élevé → filtre strict _PT_FILTER pour ne garder que le cliniquement pertinent.
    {
        "source": "pubmed_diabetes_care",
        "journal_term": f'"Diabetes Care"[Journal] AND {_PT_FILTER}',
        "label": "Diabetes Care (ADA) — RCTs DT2, Standards of Care, GLP-1/iSGLT2 (IF ~16)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Lancet Diabetes & Endocrinology ──────────────────────────────────────
    # IF ~44 — practice-changing tous sous-domaines (diabète, obésité, thyroïde,
    # surrénales). Volume faible et très sélectif à la soumission → filtre _PT_FILTER
    # suffit. Essais pivots récents : FLOW (sémaglutide rénale), SURPASS-CVOT,
    # ONWARDS 1-6, résultats CV d'anti-obésité (SELECT, SURMOUNT-MMO).
    {
        "source": "pubmed_lancet_diab_endo",
        "journal_term": f'"Lancet Diabetes Endocrinol"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Diabetes & Endocrinology — essais pivots tous sous-domaines (IF ~44)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Diabetologia ──────────────────────────────────────────────────────────
    # IF ~8 — journal officiel EASD (European Association for the Study of Diabetes).
    # Forte couverture EU (cohortes EURODABB, études scandinaves, RCTs européens).
    # Publie aussi les guidelines EASD sur DT2, obésité, complications microvasculaires.
    {
        "source": "pubmed_diabetologia",
        "journal_term": f'"Diabetologia"[Journal] AND {_PT_FILTER}',
        "label": "Diabetologia (EASD) — RCTs et guidelines EU diabète/obésité (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Journal of Clinical Endocrinology & Metabolism ────────────────────────
    # IF ~6.5 — journal officiel ENDO (Endocrine Society). Couvre tous les sous-
    # domaines : thyroïde, surrénales, hypophyse, os, diabète — avec guidelines
    # Endocrine Society (recommandations pratiques). Volume élevé → filtre strict.
    {
        "source": "pubmed_jcem",
        "journal_term": f'"J Clin Endocrinol Metab"[Journal] AND {_PT_FILTER}',
        "label": "JCEM — J Clin Endocrinol Metab (Endocrine Society, IF ~6.5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Thyroid ───────────────────────────────────────────────────────────────
    # IF ~8.5 — journal officiel ATA (American Thyroid Association). Publie les
    # guidelines ATA (nodules, cancer différencié, hyperthyroïdie, hypothyroïdie)
    # et les RCTs/cohortes : déescalade cancer papillaire, EU-TIRADS vs ATA-TIRADS,
    # surveillance active, thérapies ciblées (selpercatinib RET, cabozantinib).
    {
        "source": "pubmed_thyroid",
        "journal_term": f'"Thyroid"[Journal] AND {_PT_OR_TITLE}',
        "label": "Thyroid (ATA) — guidelines thyroïde, cancer, nodules, Basedow (IF ~8.5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── European Journal of Endocrinology ─────────────────────────────────────
    # IF ~5 — journal officiel ESE (European Society of Endocrinology). Publie les
    # Clinical Practice Guidelines ESE (acromégalie, Cushing, insuffisance
    # surrénalienne, hypoparathyroïdie, GH adulte) et les RCTs EU de référence.
    {
        "source": "pubmed_eur_j_endo",
        "journal_term": f'"Eur J Endocrinol"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Journal of Endocrinology (ESE) — guidelines pan-endo EU (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Diabetes, Obesity and Metabolism ─────────────────────────────────────
    # IF ~6.5 — Wiley. Fort volume de RCTs pharmacologiques sur DT2 et obésité :
    # essais phase 3 GLP-1 RA, iSGLT2, combinaisons, PK/PD nouvelles molécules.
    # Filtre strict pour éliminer les études uniquement pharmacocinétiques.
    {
        "source": "pubmed_diabetes_obes_metab",
        "journal_term": f'"Diabetes Obes Metab"[Journal] AND {_PT_FILTER}',
        "label": "Diabetes Obesity & Metabolism — RCTs GLP-1/iSGLT2/obésité (IF ~6.5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Osteoporosis International ────────────────────────────────────────────
    # IF ~5 — journal officiel IOF (International Osteoporosis Foundation) +
    # ESCEO. Publie les guidelines IOF/ESCEO (traitement post-ménopausique,
    # transitions thérapeutiques), les essais fracture risk (FRAX updates),
    # romosozumab, dénosumab rebond osseux. Filtre titre pour guidelines IOF.
    {
        "source": "pubmed_osteoporos_int",
        "journal_term": f'"Osteoporos Int"[Journal] AND {_PT_OR_TITLE}',
        "label": "Osteoporosis International (IOF/ESCEO) — guidelines + RCTs os (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Bone ──────────────────────────────────────────────────────────────────
    # IF ~4 — Elsevier. Journal de référence métabolisme osseux et pharmacologie
    # de l'ostéoporose. Publie les essais phase 2/3 sur nouvelles thérapies
    # anaboliques (romosozumab, abaloparatide) et antirésorbeurs (dénosumab,
    # bisphosphonates IV). Filtre strict car volume de recherche fondamentale élevé.
    {
        "source": "pubmed_bone",
        "journal_term": f'"Bone"[Journal] AND {_PT_FILTER}',
        "label": "Bone — métabolisme osseux, RCTs ostéoporose, anaboliques (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },

    # ── Clinical Endocrinology ────────────────────────────────────────────────
    # IF ~3.5 — Wiley (organ SFE/BES). Publie des études cliniques EU (cohortes
    # rares, cas index endo) et les guidelines BES (British Endocrine Societies).
    # Filtre titre pour capter les guidelines UK/EU sans PT strict.
    {
        "source": "pubmed_clin_endo",
        "journal_term": f'"Clin Endocrinol (Oxf)"[Journal] AND {_PT_OR_TITLE}',
        "label": "Clinical Endocrinology — clinique EU, guidelines BES (IF ~3.5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },

    # ── Endocrine Practice ────────────────────────────────────────────────────
    # IF ~3.2 — AACE (American Association of Clinical Endocrinology). Publie les
    # algorithmes et consensus AACE (diabète, obésité, thyroïde, ostéoporose)
    # et les clinical practice algorithms très opérationnels. Filtre titre.
    {
        "source": "pubmed_endocr_pract",
        "journal_term": f'"Endocr Pract"[Journal] AND {_PT_OR_TITLE}',
        "label": "Endocrine Practice (AACE) — consensus et algorithmes pratiques (IF ~3.2)",
        "source_type": "recommandation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },

    # ── Diabetes Research and Clinical Practice ───────────────────────────────
    # IF ~6 — Elsevier/IDF. Publie des études en vie réelle (registres, cohortes
    # internationales) et des revues systématiques sur les complications du diabète
    # (rétinopathie, neuropathie, néphropathie) et la prise en charge pratique.
    {
        "source": "pubmed_diabetes_res_clin",
        "journal_term": f'"Diabetes Res Clin Pract"[Journal] AND {_PT_OR_TITLE}',
        "label": "Diabetes Research and Clinical Practice — vie réelle, complications (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ── Journal of Endocrinological Investigation ──────────────────────────────
    # IF ~4 — SIE (Società Italiana di Endocrinologia) / Springer. Fort ancrage
    # EU (cohortes italiennes, guidelines SIE) sur les maladies rares d'endocrine
    # (phéochromocytome, incidentalome surrénalien, hypophyse). Filtre titre.
    {
        "source": "pubmed_j_endo_invest",
        "journal_term": f'"J Endocrinol Invest"[Journal] AND {_PT_OR_TITLE}',
        "label": "J Endocrinol Invest (SIE) — maladies rares, incidentalomes, guidelines EU (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },

    # ── Hormone and Metabolic Research ───────────────────────────────────────
    # IF ~3 — Thieme. Journal EU avec fort volume sur hormones et syndromes rares
    # (SOPK, hyperaldostéronisme, syndromes polyendocriniens). Filtre titre
    # renforcé pour compenser un IF modeste et un volume de recherche basique élevé.
    {
        "source": "pubmed_horm_metab_res",
        "journal_term": f'"Horm Metab Res"[Journal] AND {_PT_OR_TITLE}',
        "label": "Hormone and Metabolic Research (Thieme) — hormones rares, SOPK, EU (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },

    # ── Endocrinology ─────────────────────────────────────────────────────────
    # IF ~4.5 — Endocrine Society (Oxford). Journal translationnels mais publie
    # également les essais phase 2 et études mécanistiques à impact clinique
    # (axe GH/IGF-1, stéroïdogenèse, récepteurs hormonaux). Filtre très strict.
    {
        "source": "pubmed_endocrinology",
        "journal_term": f'"Endocrinology"[Journal] AND {_PT_FILTER}',
        "label": "Endocrinology (Endocrine Society) — translationnels à impact clinique (IF ~4.5)",
        "source_type": "innovation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },

    # ── Annales d'Endocrinologie ──────────────────────────────────────────────
    # IF ~3 — SFE (Société Française d'Endocrinologie / Masson). Journal officiel
    # de la SFE. Publie les recommandations SFE (guides de bonnes pratiques,
    # référentiels nationaux), les mises à point en langue française et les comptes
    # rendus des colloques SFE. Source privilégiée pour le contexte réglementaire FR.
    {
        "source": "pubmed_ann_endo",
        "journal_term": f'"Ann Endocrinol (Paris)"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annales d'Endocrinologie (SFE) — guidelines FR, contexte réglementaire (IF ~3)",
        "source_type": "recommandation",
        "specialty_hint": "endocrinologie",
        "min_score_hint": 6,
    },

    # ==========================================================================
    # GASTROENTÉROLOGIE, HÉPATOLOGIE ET ENDOSCOPIE DIGESTIVE
    # 16 journaux couvrant : MICI (MC/CU — biothérapies, JAKi, S1P modulateurs),
    # MASLD/MASH (resmetirom, GLP-1), hépatologie (CBP, PSC, CH, hépatites virales,
    # transplantation), cancers digestifs (CCR, pancréas, voies biliaires, œsophage),
    # endoscopie interventionnelle (ESGE/ASGE guidelines), RGO/H.pylori/SII.
    # ==========================================================================

    # ── Gut ───────────────────────────────────────────────────────────────────
    # IF ~24 — BMJ flagship gastroentérologie. Publie les grands RCTs MICI,
    # études de cohorte hépatologiques (MASLD, cirrhose), cancers GI. Volume
    # élevé → filtre _PT_FILTER strict.
    {
        "source": "pubmed_gut",
        "journal_term": f'"Gut"[Journal] AND {_PT_FILTER}',
        "label": "Gut (BMJ) — MICI, hépatologie, cancers digestifs (IF ~24)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Gastroenterology ──────────────────────────────────────────────────────
    # IF ~29 — AGA flagship, l'un des plus cités en gastro. Publie les essais
    # pivots biothérapies MICI (vedolizumab GEMINI, LUCENT mirikizumab, VIVID-1),
    # hépatologie (MASH, CH) et guidelines AGA pratique.
    {
        "source": "pubmed_gastroenterology",
        "journal_term": f'"Gastroenterology"[Journal] AND {_PT_FILTER}',
        "label": "Gastroenterology (AGA) — essais pivots MICI, MASH, hépatologie (IF ~29)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── American Journal of Gastroenterology ──────────────────────────────────
    # IF ~12 — AGA practice journal. Fort volume de RCTs pratiques, méta-analyses,
    # guidelines AGA (CCR screening, IBD, GERD). Plus orienté clinique quotidienne
    # que Gastroenterology. Filtre strict nécessaire.
    {
        "source": "pubmed_ajg",
        "journal_term": f'"Am J Gastroenterol"[Journal] AND {_PT_FILTER}',
        "label": "Am J Gastroenterol (AGA) — pratique clinique MICI, CCR, RGO (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Hepatology ────────────────────────────────────────────────────────────
    # IF ~12 — AASLD journal officiel. Publie les essais hépatologiques majeurs :
    # MASLD/MASH (lanifibranor, semaglutide ESSENCE), cirrhose, CHC, hépatites
    # virales. Guidelines AASLD practice guidance.
    {
        "source": "pubmed_hepatology",
        "journal_term": f'"Hepatology"[Journal] AND {_PT_FILTER}',
        "label": "Hepatology (AASLD) — MASLD/MASH, cirrhose, CHC, hépatites virales (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Journal of Hepatology ─────────────────────────────────────────────────
    # IF ~26 — EASL flagship, journal européen de référence en hépatologie.
    # Publie les EASL Clinical Practice Guidelines (CBP, PSC, CH, cirrhose),
    # essais majeurs (IMbrave150 update, HIMALAYA, POISE/ELATIVE/RESPONSE CBP).
    {
        "source": "pubmed_j_hepatol",
        "journal_term": f'"J Hepatol"[Journal] AND {_PT_FILTER}',
        "label": "J Hepatol (EASL) — guidelines hépatologie, CBP, CH, MASH (IF ~26)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Lancet Gastroenterology & Hepatology ──────────────────────────────────
    # IF ~36 — très sélectif, essais practice-changing. Publie VARSITY
    # (vedolizumab vs adalimumab), MAESTRO-NASH (resmetirom), LUCENT extension,
    # PRODIGE 24, TOPAZ-1. Volume faible → _PT_FILTER suffit.
    {
        "source": "pubmed_lancet_gastro",
        "journal_term": f'"Lancet Gastroenterol Hepatol"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Gastroenterology & Hepatology — essais pivots all (IF ~36)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Alimentary Pharmacology & Therapeutics ────────────────────────────────
    # IF ~8 — Wiley/BSG. Fort volume de RCTs pratiques et méta-analyses sur
    # MICI (biothérapies, optimisation de dose), RGO, H. pylori, SII, microbiote.
    # Filtre strict nécessaire (volume important).
    {
        "source": "pubmed_apt",
        "journal_term": f'"Aliment Pharmacol Ther"[Journal] AND {_PT_FILTER}',
        "label": "Aliment Pharmacol Ther (BSG/Wiley) — MICI pratique, RGO, H.pylori (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Clinical Gastroenterology and Hepatology ──────────────────────────────
    # IF ~12 — AGA practice journal. Priorité aux études d'implémentation,
    # cohortes prospectives, guidelines AGA pratique (MASLD, CCR surveillance,
    # biopsie hépatique). Filtre strict.
    {
        "source": "pubmed_cgh",
        "journal_term": f'"Clin Gastroenterol Hepatol"[Journal] AND {_PT_FILTER}',
        "label": "Clin Gastroenterol Hepatol (AGA) — implémentation, CCR, MASLD (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Journal of Crohn's and Colitis ────────────────────────────────────────
    # IF ~8 — ECCO journal officiel. Source de référence pour les ECCO Guidelines
    # (MC et CU), consensus européens biothérapies MICI, chirurgie MICI,
    # surveillance coloscopique CU. Filtre _PT_OR_TITLE pour capter les guidelines.
    {
        "source": "pubmed_jcc",
        "journal_term": f'"J Crohns Colitis"[Journal] AND {_PT_OR_TITLE}',
        "label": "J Crohn's Colitis (ECCO) — guidelines MICI européens, biothérapies (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Endoscopy ─────────────────────────────────────────────────────────────
    # IF ~11 — ESGE journal officiel. Publie les guidelines ESGE (polypectomie,
    # CPRE, surveillance coloscopique, ESD/EMR, hémostase, IA en endoscopie).
    # Source prioritaire pour le réglementaire endoscopique. _PT_OR_TITLE pour
    # capter les guidelines.
    {
        "source": "pubmed_endoscopy",
        "journal_term": f'"Endoscopy"[Journal] AND {_PT_OR_TITLE}',
        "label": "Endoscopy (ESGE) — guidelines endoscopie interventionnelle (IF ~11)",
        "source_type": "recommandation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Gastrointestinal Endoscopy ────────────────────────────────────────────
    # IF ~7 — ASGE journal officiel. Guidelines ASGE (CPRE, EUS, capsule),
    # RCTs endoscopiques (hémostase, POEM, bariatrique endoscopique).
    {
        "source": "pubmed_gie",
        "journal_term": f'"Gastrointest Endosc"[Journal] AND {_PT_FILTER}',
        "label": "Gastrointest Endosc (ASGE) — guidelines endoscopie, RCTs interventionnels (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── JHEP Reports ─────────────────────────────────────────────────────────
    # IF ~7 — EASL open-access. Publie des RCTs et cohortes hépatologiques
    # (MASLD, CBP, PSC, CHC) non acceptés dans J Hepatol par compétition.
    # Croissance rapide depuis 2019, de plus en plus impactant.
    {
        "source": "pubmed_jhep_rep",
        "journal_term": f'"JHEP Rep"[Journal] AND {_PT_FILTER}',
        "label": "JHEP Reports (EASL open-access) — hépatologie, MASH, CBP (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Liver International ───────────────────────────────────────────────────
    # IF ~7 — EASL affiliate. Essais hépatologiques (MASLD fibrose, CBP, VHB/VHD),
    # méta-analyses scores fibrose (FIB-4, LSM), transplantation hépatique.
    {
        "source": "pubmed_liver_int",
        "journal_term": f'"Liver Int"[Journal] AND {_PT_FILTER}',
        "label": "Liver International (EASL) — MASLD, VHB/VHD, transplantation (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Digestive Endoscopy ───────────────────────────────────────────────────
    # IF ~4 — JGES (Japan Gastroenterological Endoscopy Society). Techniques
    # endoscopiques avancées (ESD colorectal et gastrique, POEM, traction devices),
    # résultats issus des centres japonais de référence mondiale en endoscopie.
    {
        "source": "pubmed_dig_endosc",
        "journal_term": f'"Dig Endosc"[Journal] AND {_PT_FILTER}',
        "label": "Digestive Endoscopy (JGES) — ESD, POEM, techniques avancées (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── European Journal of Gastroenterology & Hepatology ────────────────────
    # IF ~3 — Lippincott/Wolters Kluwer. Études européennes pratiques, méta-analyses
    # sur biothérapies MICI et hépatologie, cohortes françaises (SNFGE/AFEF).
    {
        "source": "pubmed_ejgh",
        "journal_term": f'"Eur J Gastroenterol Hepatol"[Journal] AND {_PT_FILTER}',
        "label": "Eur J Gastroenterol Hepatol — cohortes EU pratiques, MICI, hépatologie (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ── Journal of Gastroenterology and Hepatology ────────────────────────────
    # IF ~4 — Wiley/AASLD-affiliate. Méta-analyses et RCTs Asie-Pacifique avec
    # transposabilité EU (H. pylori résistances, MASLD, CCR dépistage). Filtre
    # strict pour population pertinente FR/EU.
    {
        "source": "pubmed_j_gastro_hepatol",
        "journal_term": f'"J Gastroenterol Hepatol"[Journal] AND {_PT_FILTER}',
        "label": "J Gastroenterol Hepatol — H.pylori, MASLD, CCR Asie-Pacifique (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 6,
    },

    # ==========================================================================
    # GÉRIATRIE ET GÉRONTOLOGIE
    # 16 journaux couvrant : démences (Alzheimer, vasculaire, corps de Lewy),
    # fragilité / sarcopénie, chutes / fractures, polymédication / iatrogénie,
    # dénutrition, onco-gériatrie, soins en EHPAD, fin de vie, évaluation
    # gérontologique approfondie (EGA/CGA), prévention du déclin fonctionnel.
    # ==========================================================================

    # ── Age and Ageing ────────────────────────────────────────────────────────
    # IF ~13 — British Geriatrics Society (BGS) flagship. Publie les RCTs et
    # méta-analyses les plus impactants en gériatrie clinique (fragilité, chutes,
    # démences, polymédication). Contribue aux STOPP/START guidelines.
    {
        "source": "pubmed_age_ageing",
        "journal_term": f'"Age Ageing"[Journal] AND {_PT_FILTER}',
        "label": "Age and Ageing (BGS) — fragilité, chutes, démences, polymédication (IF ~13)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Journal of the American Geriatrics Society ────────────────────────────
    # IF ~7 — AGS flagship. Publie les AGS Beers Criteria (mise à jour 2023),
    # RCTs gériatriques (polymédication, chutes, démences, transitions de soins).
    # Source de référence pour les critères de prescription inappropriée.
    {
        "source": "pubmed_jags",
        "journal_term": f'"J Am Geriatr Soc"[Journal] AND {_PT_FILTER}',
        "label": "J Am Geriatr Soc (AGS) — Beers 2023, polymédication, transitions soins (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Lancet Healthy Longevity ──────────────────────────────────────────────
    # IF ~20 — Lancet group, lancé en 2020, très sélectif. Essais practice-changing
    # en vieillissement et gériatrie (prévention démence, fragilité, nutrition,
    # multimorbidité). Volume faible → _PT_FILTER suffit.
    {
        "source": "pubmed_lancet_healthy_longev",
        "journal_term": f'"Lancet Healthy Longev"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Healthy Longevity — prévention démence, fragilité, multimorbidité (IF ~20)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Alzheimer's & Dementia ────────────────────────────────────────────────
    # IF ~14 — Alzheimer's Association flagship. Publie les essais pivots
    # anti-amyloïdes (CLARITY AD lecanemab, TRAILBLAZER-ALZ 2 donanemab),
    # biomarqueurs (PET amyloïde/tau, plasma p-tau 217), critères diagnostiques
    # NIA-AA 2024 maladie d'Alzheimer. _PT_OR_TITLE pour capter les guidelines.
    {
        "source": "pubmed_alzheimers_dement",
        "journal_term": f'"Alzheimers Dement"[Journal] AND {_PT_OR_TITLE}',
        "label": "Alzheimer's & Dementia — anti-amyloïdes, biomarqueurs, critères NIA-AA (IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Journal of Gerontology: Medical Sciences ──────────────────────────────
    # IF ~6 — Gerontological Society of America (GSA). Études mécanistiques et
    # cliniques vieillissement biologique, sarcopénie (EWGSOP2), fragilité,
    # comorbidités chroniques du sujet âgé.
    {
        "source": "pubmed_j_gerontol_med",
        "journal_term": f'"J Gerontol A Biol Sci Med Sci"[Journal] AND {_PT_FILTER}',
        "label": "J Gerontol: Med Sci (GSA) — sarcopénie, fragilité, vieillissement biologique (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Journal of the American Medical Directors Association ─────────────────
    # IF ~6 — JAMDA, AMDA (The Society for Post-Acute and Long-Term Care Medicine).
    # Source de référence pour la pratique en EHPAD (long-term care) : soins
    # palliatifs, démences en institution, prévention escarres, transitions.
    {
        "source": "pubmed_jamda",
        "journal_term": f'"J Am Med Dir Assoc"[Journal] AND {_PT_FILTER}',
        "label": "JAMDA (AMDA) — EHPAD, soins palliatifs, démences institutionnalisées (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── European Geriatric Medicine ───────────────────────────────────────────
    # IF ~4 — EUGMS journal officiel. Publie les EUGMS guidelines, consensus
    # européens (fragilité, sarcopénie, polymédication STOPP/START), essais
    # européens en gériatrie. Source privilégiée pour le contexte EU/FR.
    {
        "source": "pubmed_eur_geriatr_med",
        "journal_term": f'"Eur Geriatr Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Eur Geriatr Med (EUGMS) — guidelines EU fragilité, STOPP/START, sarcopénie (IF ~4)",
        "source_type": "recommandation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── International Journal of Geriatric Psychiatry ─────────────────────────
    # IF ~4 — Wiley. RCTs et méta-analyses en psychiatrie de la personne âgée :
    # dépression du sujet âgé (sérotoninergiques, ECT), delirium (prévention,
    # halopéridol vs dexmédétomidine), troubles du comportement dans les démences,
    # anxiété et insomnies chez le sujet âgé.
    {
        "source": "pubmed_int_j_geriatr_psychiatry",
        "journal_term": f'"Int J Geriatr Psychiatry"[Journal] AND {_PT_FILTER}',
        "label": "Int J Geriatr Psychiatry — dépression âgé, delirium, troubles comportement démence (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Journal of Alzheimer's Disease ───────────────────────────────────────
    # IF ~4 — IOS Press. Recherche translationnelle et études cliniques sur les
    # démences (biomarqueurs sanguins, IRM volumétrique, interventions non-
    # pharmacologiques). Complément d'Alzheimer's & Dementia pour les études
    # mécanistiques à transposabilité clinique.
    {
        "source": "pubmed_j_alzheimers_dis",
        "journal_term": f'"J Alzheimers Dis"[Journal] AND {_PT_FILTER}',
        "label": "J Alzheimer's Disease — biomarqueurs, interventions non-pharmaco démences (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Clinical Interventions in Aging ──────────────────────────────────────
    # IF ~3 — Dove Medical Press (open-access). RCTs et cohortes gériatriques
    # pratiques (chutes, réhabilitation, polymédication, dénutrition). Volume
    # élevé → filtre strict.
    {
        "source": "pubmed_clin_interv_aging",
        "journal_term": f'"Clin Interv Aging"[Journal] AND {_PT_FILTER}',
        "label": "Clin Interv Aging (Dove) — chutes, réhabilitation, dénutrition âgé (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 7,
    },

    # ── BMC Geriatrics ────────────────────────────────────────────────────────
    # IF ~4 — BioMed Central (open-access). Cohortes prospectives, études
    # interventionnelles gériatriques (CGA, EHPAD, multimorbidité, soins intégrés).
    # Fort volume → filtre très strict nécessaire.
    {
        "source": "pubmed_bmc_geriatr",
        "journal_term": f'"BMC Geriatr"[Journal] AND {_PT_FILTER}',
        "label": "BMC Geriatrics — CGA, multimorbidité, soins intégrés (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 7,
    },

    # ── Maturitas ─────────────────────────────────────────────────────────────
    # IF ~4 — Elsevier. Ménopause, vieillissement hormonal (andropause, DHEA),
    # ostéoporose et fractures, maladies cardiovasculaires chez la femme âgée.
    # Complémentaire gériatrie pour les aspects métaboliques et hormonaux du
    # vieillissement.
    {
        "source": "pubmed_maturitas",
        "journal_term": f'"Maturitas"[Journal] AND {_PT_FILTER}',
        "label": "Maturitas — ménopause, ostéoporose, vieillissement hormonal (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Journal of Nutrition, Health & Aging ─────────────────────────────────
    # IF ~4 — Springer. Dénutrition du sujet âgé (critères GLIM, MNA, MUST),
    # sarcopénie (apports protéiques, leucine, supplémentation), micronutriments
    # (vitamine D, B12, folates), régime méditerranéen et vieillissement cognitif.
    {
        "source": "pubmed_j_nutr_health_aging",
        "journal_term": f'"J Nutr Health Aging"[Journal] AND {_PT_FILTER}',
        "label": "J Nutr Health Aging — dénutrition GLIM, sarcopénie, micronutriments (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Aging Clinical and Experimental Research ──────────────────────────────
    # IF ~4 — Springer. Résultats cliniques vieillissement (fragilité, chutes,
    # cognition, multimorbidité), études observationnelles européennes et
    # méta-analyses en gériatrie pratique.
    {
        "source": "pubmed_aging_clin_exp_res",
        "journal_term": f'"Aging Clin Exp Res"[Journal] AND {_PT_FILTER}',
        "label": "Aging Clin Exp Res — fragilité, chutes, cognition, multimorbidité EU (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 6,
    },

    # ── Geriatrics & Gerontology International ────────────────────────────────
    # IF ~3 — Wiley/Japan Geriatrics Society. Études Asie-Pacifique avec
    # transposabilité EU (sarcopénie, fragilité, démences, chutes). Données
    # japonaises de référence sur les définitions sarcopénie/fragilité.
    {
        "source": "pubmed_geriatr_gerontol_int",
        "journal_term": f'"Geriatr Gerontol Int"[Journal] AND {_PT_FILTER}',
        "label": "Geriatr Gerontol Int — sarcopénie/fragilité Asie-Pacifique, données japonnaises (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 7,
    },

    # ── Gerontology ───────────────────────────────────────────────────────────
    # IF ~4 — Karger. Mécanismes du vieillissement avec transposabilité clinique
    # (télomères, inflammation chronique / inflammaging, sénescence cellulaire),
    # biomarqueurs du vieillissement biologique et essais d'interventions
    # anti-aging (metformine TAME trial, rapamycine, sénolytiques).
    {
        "source": "pubmed_gerontology",
        "journal_term": f'"Gerontology"[Journal] AND {_PT_FILTER}',
        "label": "Gerontology (Karger) — inflammaging, sénolytiques, biomarqueurs vieillissement (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "geriatrie",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # GYNÉCOLOGIE-OBSTÉTRIQUE ET MÉDECINE DE LA REPRODUCTION
    # 16 journaux couvrant : gynéco-oncologie (endomètre, col, ovaire — PARP inhibiteurs,
    # immunothérapie, bevacizumab), endométriose (ESHRE 2022, agonistes GnRH-add-back,
    # relugolix/linzagolix AMM EU 2022), PMA/fertilité (FIV, IIU, PGT, don ovocytes),
    # ménopause/THM (IMS/NAMS 2023), myomes (ulipristal retiré, relugolix, HIFU),
    # prolapsus/IU (sacropexie robot, TVT/TOT), contraception (HAS 2022), dépistage
    # HPV/CIN, prééclampsie (aspirine ASPRE, sFlt1/PlGF).
    # ==========================================================================

    # ── American Journal of Obstetrics & Gynecology (AJOG) ───────────────────
    # IF ~10 — flagship de l'ACOG/SMFM. Publie les grandes études multicentriques
    # US (obstétrique, PMA, gynéco-oncologie), guidelines ACOG pratique obstétricale,
    # méta-analyses en réseau NMA. Volume élevé → filtre _PT_FILTER strict.
    {
        "source": "pubmed_ajog",
        "journal_term": f'"Am J Obstet Gynecol"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Obstetrics & Gynecology (AJOG) — guidelines ACOG + RCTs (IF ~10)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Obstetrics & Gynecology (Green Journal / ACOG) ───────────────────────
    # IF ~7 — journal officiel ACOG (American College of Ob-Gyn). Publie les
    # ACOG Practice Bulletins et Committee Opinions (référence réglementaire US),
    # essais cliniques randomisés, lettres de pratique courante.
    # _PT_OR_TITLE pour capturer les bulletins (labellisés "guideline" en titre).
    {
        "source": "pubmed_obstet_gynecol",
        "journal_term": f'"Obstet Gynecol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Obstetrics & Gynecology (ACOG Green Journal) — Practice Bulletins + RCTs (IF ~7)",
        "source_type": "recommandation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Fertility & Sterility (ASRM) ─────────────────────────────────────────
    # IF ~8 — journal officiel ASRM. THE référence PMA mondiale : FIV, ICSI,
    # PGT-A/M/SR, don ovocytes, stimulation ovarienne, endométriose-fertilité,
    # guidelines ASRM/ESHRE. Inclut les ASRM Committee Opinions (réglementaire PMA).
    {
        "source": "pubmed_fertil_steril",
        "journal_term": f'"Fertil Steril"[Journal] AND {_PT_OR_TITLE}',
        "label": "Fertility & Sterility (ASRM) — PMA, FIV, ICSI, endométriose-fertilité (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── BJOG — British Journal of Obstetrics & Gynaecology ───────────────────
    # IF ~6 — journal officiel RCOG. Publie les RCTs multicentriques UK/EU,
    # les guidelines RCOG (Green Top Guidelines — obstétrique, ménopause, HPV),
    # méta-analyses, études de cohorte nationales (bases UK).
    # _PT_OR_TITLE pour capturer les Green Top Guidelines.
    {
        "source": "pubmed_bjog",
        "journal_term": f'"BJOG"[Journal] AND {_PT_OR_TITLE}',
        "label": "BJOG (RCOG) — Green Top Guidelines + RCTs multicentriques UK/EU (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Ultrasound in Obstetrics & Gynecology (ISUOG) ────────────────────────
    # IF ~7 — journal officiel ISUOG. Publie les guidelines ISUOG (consensus
    # diagnostic prénatal, markers d'anomalie chromosomique, dépistage prééclampsie
    # sFlt1/PlGF), études de validation diagnostique, triage de premier trimestre.
    {
        "source": "pubmed_ultrasound_og",
        "journal_term": f'"Ultrasound Obstet Gynecol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Ultrasound in Obstetrics & Gynecology (ISUOG) — guidelines écho + dépistage (IF ~7)",
        "source_type": "recommandation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Gynecologic Oncology (SGO) ────────────────────────────────────────────
    # IF ~6 — journal officiel SGO (Society of Gynecologic Oncology). Publie
    # les essais phase 2/3 pivots en gynéco-oncologie (endomètre, col, ovaire,
    # vulve) : PARP inhibitors, immunothérapie (pembrolizumab, dostarlimab),
    # bevacizumab, carboplatine/taxane, chirurgie, radiothérapie pelvienne.
    {
        "source": "pubmed_gynecol_oncol",
        "journal_term": f'"Gynecol Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Gynecologic Oncology (SGO) — PARP inhibiteurs, immunothérapie, chirurgie (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Human Reproduction (ESHRE) ────────────────────────────────────────────
    # IF ~6 — journal officiel ESHRE. Publie les guidelines ESHRE (endométriose
    # 2022, SOPK, IIU, ART, médecine foetale), RCTs multicentriques EU sur PMA,
    # études de registre européen ART. Couverture ESHRE + European IVF Monitoring.
    {
        "source": "pubmed_hum_reprod",
        "journal_term": f'"Hum Reprod"[Journal] AND {_PT_OR_TITLE}',
        "label": "Human Reproduction (ESHRE) — guidelines ESHRE + PMA multicentriques EU (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Menopause (NAMS) ──────────────────────────────────────────────────────
    # IF ~3 — journal officiel NAMS (North American Menopause Society). THE référence
    # pour le THM : NAMS Position Statement 2022/2023, données sur E2/progestérone
    # naturelle vs progestatifs de synthèse, risque CV/sein, genitourinaire,
    # osseux. Filtre titre renforcé pour ne garder que les articles pratiques.
    {
        "source": "pubmed_menopause_j",
        "journal_term": f'"Menopause"[Journal] AND {_PT_OR_TITLE}',
        "label": "Menopause (NAMS) — THM, E2/progestérone naturelle, risque CV/sein (IF ~3)",
        "source_type": "recommandation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ── International Journal of Gynecological Cancer (IGCS) ─────────────────
    # IF ~4 — journal officiel IGCS. Publie essais cliniques en gynéco-oncologie
    # (endomètre, col, ovaire, vulve), études multicentriques internationales,
    # analyses de sous-groupes des essais pivots (RUBY, KEYNOTE-826, SOLO-1).
    {
        "source": "pubmed_ijgc",
        "journal_term": f'"Int J Gynecol Cancer"[Journal] AND {_PT_FILTER}',
        "label": "Int J Gynecological Cancer (IGCS) — gynéco-oncologie multicentriques (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── Journal of Minimally Invasive Gynecology (JMIG) ──────────────────────
    # IF ~4 — journal AAGL (laparoscopie/hystéroscopie). Publie RCTs sur chirurgie
    # mini-invasive (cœlioscopie, NOTES, robot), hystéroscopie diagnostique et
    # opératoire, sacropexie laparoscopique/robot vs voie vaginale, ERAS en gyn.
    {
        "source": "pubmed_jmig",
        "journal_term": f'"J Minim Invasive Gynecol"[Journal] AND {_PT_FILTER}',
        "label": "J Minimally Invasive Gynecology (AAGL) — laparoscopie, hystéroscopie, robot (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 6,
    },

    # ── European Journal of Obstetrics & Gynecology and Reproductive Biology ──
    # IF ~3 — journal européen généraliste (Elsevier). Publie des études cliniques
    # multicentriques EU, revues systématiques, études de cohorte européennes sur
    # obstétrique et gynécologie. Bonne couverture pratiques européennes.
    {
        "source": "pubmed_ejogrb",
        "journal_term": f'"Eur J Obstet Gynecol Reprod Biol"[Journal] AND {_PT_FILTER}',
        "label": "European J Obstetrics & Gynecology Reprod Biol — études EU (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ── Acta Obstetricia et Gynecologica Scandinavica (AOGS / NFOG) ──────────
    # IF ~4 — journal officiel NFOG (sociétés scandinaves). Publie les RCTs
    # multicentriques nord-européens (registres nationaux suédois/danois/finlandais),
    # guidelines NFOG/DSOG (dépistage HPV, prééclampsie, accouchement normal).
    {
        "source": "pubmed_aogs",
        "journal_term": f'"Acta Obstet Gynecol Scand"[Journal] AND {_PT_FILTER}',
        "label": "Acta Obstet Gynecol Scand (NFOG) — RCTs nordiques + registres nationaux (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ── Journal of Gynecology Obstetrics and Human Reproduction (CNGOF) ──────
    # IF ~2 — journal officiel CNGOF (Collège National des Gynécologues-Obstétriciens
    # Français). THE source réglementaire française en gynécologie : Recommandations
    # pour la Pratique Clinique (RPC) CNGOF (dépistage CCU, HPV, ménopause, PMA,
    # endométriose). Filtre titre pour capturer les RPC.
    {
        "source": "pubmed_jgohr",
        "journal_term": f'"J Gynecol Obstet Hum Reprod"[Journal] AND {_PT_OR_TITLE}',
        "label": "J Gynecology Obstetrics & Human Reprod (CNGOF) — RPC françaises (IF ~2)",
        "source_type": "recommandation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ── Reproductive BioMedicine Online (RBM Online) ─────────────────────────
    # IF ~4 — Elsevier/RBMO Ltd. Publie les études cliniques PMA : PGT-A/M,
    # endométriose et FIV, vitrification, cumulative live birth rate, registres
    # ART. Volume modéré, qualité clinique homogène.
    {
        "source": "pubmed_rbm_online",
        "journal_term": f'"Reprod Biomed Online"[Journal] AND {_PT_FILTER}',
        "label": "Reproductive BioMedicine Online — PGT-A, FIV, vitrification (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ── Archives of Gynecology and Obstetrics (AGO Springer) ─────────────────
    # IF ~3 — journal Springer international. Publie des études cliniques
    # multicentriques sur obstétrique pathologique, chirurgie gynécologique,
    # gynéco-oncologie. Forte proportion de cohortes et revues systématiques EU.
    {
        "source": "pubmed_arch_gynecol",
        "journal_term": f'"Arch Gynecol Obstet"[Journal] AND {_PT_FILTER}',
        "label": "Archives of Gynecology & Obstetrics (Springer) — obstétrique + gyn chirurgicale (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ── Gynecological Endocrinology ───────────────────────────────────────────
    # IF ~2 — journal Taylor & Francis. Publie les études cliniques en endocrinologie
    # reproductive : SOPK (metformine, létrozole, contraceptifs), thyroïde et
    # grossesse, ménopause précoce (IOP), traitement hormonal de substitution,
    # amménorrhée hypothalamique. Filtre titre pour éviter les fondamentaux.
    {
        "source": "pubmed_gynecol_endocrinol",
        "journal_term": f'"Gynecol Endocrinol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Gynecological Endocrinology — SOPK, ménopause, IOP, THM (IF ~2)",
        "source_type": "innovation",
        "specialty_hint": "gynecologie",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # HÉMATOLOGIE CLINIQUE (ADULTE)
    # 16 journaux couvrant : leucémies aiguës (LAM venetoclax+aza VIALE-A, LAL
    # blinatumomab/inotuzumab, CAR-T), LLC (BTK inhibiteurs ibrutinib/acalabrutinib/
    # zanubrutinib, venetoclax+obinutuzumab), lymphomes (pola-R-CHP POLARIX, CAR-T
    # axi-cel/tisa-cel), myélome multiple (daratumumab MAIA/CASSIOPEIA, ide-cel/cilta-cel
    # CAR-T AMM EU), SMD (luspatercept MEDALIST/COMMANDS), NMP (ruxolitinib,
    # ropeginterféron), MTEV-cancer (AOD HOKUSAI/SELECT-D), hémophilie (emicizumab
    # HAVEN, thérapie génique), AHAI/PTI (rituximab, TPO-RA), GVH (ruxolitinib
    # REACH2, belumosudil). Réglementaire : EHA/ESMO/ASH/ISTH guidelines.
    # ==========================================================================

    # ── Blood (ASH) ───────────────────────────────────────────────────────────
    # IF ~25 — journal officiel ASH. THE référence hématologique mondiale. Publie
    # les essais pivots de toutes les hémopathies, les mises à jour des guidelines
    # ASH annuelles (MTEV, HIT, drépanocytose, hémophilie, PTI). Volume élevé →
    # filtre _PT_FILTER strict pour garder uniquement essais et guidelines.
    {
        "source": "pubmed_blood",
        "journal_term": f'"Blood"[Journal] AND {_PT_FILTER}',
        "label": "Blood (ASH) — essais pivots toutes hémopathies + guidelines ASH (IF ~25)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Leukemia (Nature Portfolio) ───────────────────────────────────────────
    # IF ~12 — journal Nature hématologie. Publie les grands essais en leucémies,
    # SMD, NMP, et les méta-analyses sur nouvelles cibles moléculaires (FLT3, IDH,
    # BCL-2). Forte couverture LAM et LLC avancée.
    {
        "source": "pubmed_leukemia",
        "journal_term": f'"Leukemia"[Journal] AND {_PT_FILTER}',
        "label": "Leukemia (Nature) — LAM, LAL, LLC, SMD essais pivots (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Haematologica (EHA) ───────────────────────────────────────────────────
    # IF ~9 — journal officiel EHA (European Haematology Association). Publie les
    # essais multicentriques européens, les guidelines EHA, les études de registre
    # EURONET/EBMT. Forte pertinence pour la pratique européenne et française (EHA).
    {
        "source": "pubmed_haematologica",
        "journal_term": f'"Haematologica"[Journal] AND {_PT_FILTER}',
        "label": "Haematologica (EHA) — essais EU + guidelines EHA (IF ~9)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── American Journal of Hematology ────────────────────────────────────────
    # IF ~12 — journal Wiley généraliste hématologie. Publie des essais cliniques,
    # études de cohorte sur drépanocytose (voxelotor, crizanlizumab), MTEV,
    # hémopathies bénignes. Volume modéré, qualité clinique élevée.
    {
        "source": "pubmed_am_j_hematol",
        "journal_term": f'"Am J Hematol"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Hematology — drépanocytose, MTEV, hémopathies bénignes (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Lancet Haematology ────────────────────────────────────────────────────
    # IF ~25 — journal Lancet dédié à l'hématologie. Publie les RCTs practice-
    # changing (CAR-T long-term outcomes, nouveaux BTK inhibiteurs, thérapies
    # géniques hémoglobinopathies). Volume faible mais très sélectif.
    {
        "source": "pubmed_lancet_haematol",
        "journal_term": f'"Lancet Haematol"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Haematology — CAR-T, BTK inhibiteurs, thérapies géniques (IF ~25)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── British Journal of Haematology ────────────────────────────────────────
    # IF ~6 — journal officiel BSH (British Society for Haematology). Publie les
    # guidelines BSH (MTEV, HIT, plaquettes, hémophilie, lymphomes), essais
    # cliniques UK/EU, données de registre national UK (NCRI). Très référencé
    # en pratique hématologique européenne.
    # _PT_OR_TITLE pour les guidelines BSH.
    {
        "source": "pubmed_br_j_haematol",
        "journal_term": f'"Br J Haematol"[Journal] AND {_PT_OR_TITLE}',
        "label": "British J Haematology (BSH) — guidelines BSH + essais UK/EU (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Blood Advances (ASH open access) ─────────────────────────────────────
    # IF ~7 — journal ASH open access. Publie des essais phase 2/3, études de
    # cohorte, analyses de sous-groupes des grandes études ASH. Complément de
    # Blood pour les études de registre et les données de vie réelle.
    {
        "source": "pubmed_blood_adv",
        "journal_term": f'"Blood Adv"[Journal] AND {_PT_FILTER}',
        "label": "Blood Advances (ASH open access) — cohortes, registres, essais phase 2/3 (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 7,
    },

    # ── Journal of Hematology & Oncology ──────────────────────────────────────
    # IF ~28 — journal BioMed Central (accès libre). Publie revues systématiques
    # et méta-analyses sur thérapies ciblées (BTK inhibiteurs, CAR-T, anticorps
    # bispécifiques), mécanismes de résistance aux traitements hématologiques.
    {
        "source": "pubmed_j_hematol_oncol",
        "journal_term": f'"J Hematol Oncol"[Journal] AND {_PT_FILTER}',
        "label": "J Hematology & Oncology — méta-analyses BTK/CAR-T/bispécifiques (IF ~28)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Bone Marrow Transplantation (BMT) ────────────────────────────────────
    # IF ~5 — journal Nature/EBMT. THE référence greffe de cellules souches :
    # allogreffe (régimes de conditionnement, GVHD, infection post-greffe),
    # autogreffe (myélome, lymphomes), guidelines EBMT. Données registre EBMT.
    {
        "source": "pubmed_bone_marrow_transplant",
        "journal_term": f'"Bone Marrow Transplant"[Journal] AND {_PT_FILTER}',
        "label": "Bone Marrow Transplantation (EBMT) — allogreffe, GVH, registre EBMT (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Thrombosis & Haemostasis (ISTH journal) ───────────────────────────────
    # IF ~6 — journal de l'ISTH (International Society on Thrombosis and Haemostasis).
    # Publie les essais sur anticoagulants, antiplaquettaires, hémophilies, MTEV
    # en cancer, HIT. Guidelines ISTH (AOD, HIT, thrombophilie).
    {
        "source": "pubmed_thromb_haemost",
        "journal_term": f'"Thromb Haemost"[Journal] AND {_PT_FILTER}',
        "label": "Thrombosis & Haemostasis (ISTH) — anticoagulants, HIT, MTEV cancer (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Journal of Thrombosis and Haemostasis ─────────────────────────────────
    # IF ~7 — journal officiel ISTH (numérique). Publie les RCTs sur AOD, hémostase,
    # thrombophilies, anticorps antiphospholipides (SAPS). Complémentaire de
    # Thromb Haemost pour les études cliniques interventionnelles.
    {
        "source": "pubmed_j_thromb_haemost",
        "journal_term": f'"J Thromb Haemost"[Journal] AND {_PT_FILTER}',
        "label": "J Thrombosis & Haemostasis — AOD, APS, thrombophilies, hémostase (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 6,
    },

    # ── Annals of Hematology ─────────────────────────────────────────────────
    # IF ~4 — journal Springer/EHA affilié. Publie des essais cliniques
    # multicentriques européens, études de cohorte et mises à point sur hémopathies
    # malignes et bénignes. Bonne couverture des données de vie réelle européens.
    {
        "source": "pubmed_ann_hematol",
        "journal_term": f'"Ann Hematol"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Hematology (Springer/EHA) — essais EU, vie réelle, hémopathies (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 7,
    },

    # ── Leukemia & Lymphoma ───────────────────────────────────────────────────
    # IF ~3 — journal Taylor & Francis (ex-Hematology and Oncology). Publie des
    # essais cliniques et études de cohorte sur LLC, lymphomes non-Hodgkiniens,
    # leucémies chroniques. Complément utile pour sous-domaines spécifiques.
    {
        "source": "pubmed_leuk_lymphoma",
        "journal_term": f'"Leuk Lymphoma"[Journal] AND {_PT_FILTER}',
        "label": "Leukemia & Lymphoma — LLC, LNH, leucémies chroniques (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 7,
    },

    # ── European Journal of Haematology ──────────────────────────────────────
    # IF ~4 — journal Wiley/Nordic. Publie des essais cliniques et des études de
    # cohorte nordiques/européens, avec forte couverture des hémopathies bénignes
    # (AHAI, PTI, hémorragies non oncologiques), thalassémies, hémoglobinopathies.
    {
        "source": "pubmed_eur_j_haematol",
        "journal_term": f'"Eur J Haematol"[Journal] AND {_PT_FILTER}',
        "label": "European J Haematology — hémopathies bénignes, thalassémies, nordiques (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 7,
    },

    # ── Hematological Oncology ────────────────────────────────────────────────
    # IF ~3 — journal Wiley. Publie des essais cliniques en onco-hématologie,
    # études de registre, mises à point sur lymphomes, myélome, hémopathies rares.
    # _PT_OR_TITLE pour capturer les guidelines publiées dans ce journal.
    {
        "source": "pubmed_hematol_oncol",
        "journal_term": f'"Hematol Oncol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Hematological Oncology — lymphomes, myélome, hémopathies rares (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 7,
    },

    # ── Clinical Lymphoma, Myeloma and Leukemia ───────────────────────────────
    # IF ~3 — journal Elsevier. Publie des études de cohorte, analyses de registre
    # SEER/NCDB, méta-analyses sur LLC, myélome, lymphomes de Hodgkin et non-
    # Hodgkiniens. Pertinent pour les données pharmaco-économiques et patterns \
    # de traitement en pratique réelle.
    {
        "source": "pubmed_clin_lymphoma_myeloma_leuk",
        "journal_term": f'"Clin Lymphoma Myeloma Leuk"[Journal] AND {_PT_FILTER}',
        "label": "Clin Lymphoma Myeloma Leukemia — registres SEER/NCDB, pharmaco-économie (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "hematologie",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # INFECTIOLOGIE — MALADIES INFECTIEUSES, MICROBIOLOGIE CLINIQUE, VIROLOGIE
    # 16 journaux couvrant : VIH (INI 2e génération, injectables LA, lenacapavir),
    # VHC (pan-génotypiques SOF/VEL±VOX, GLE/PIB), VHB/VHD (TAF, bulevirtide),
    # antibiorésistance (BMR/BLSE/KPC/MBL : CAZ-AVI, ATM-AVI, C/T, IMR),
    # antifongiques (échinocandines, ibrexafungerp, olorofim), sepsis/choc septique
    # (SSC 2021), tuberculose MDR/XDR (BPaL bédaquiline+prétomanid+linézolide),
    # IST (gonorrhée résistante IUSTI 2022, syphilis, chlamydia), paludisme
    # (artémisinine, vaccin RTS,S OMS 2021), COVID-19 (antiviraux), CMV greffe.
    # Réglementaire : SPILF/CMIT, ESC IE 2023, ECDC, guidelines IDSA/ESCMID.
    # ==========================================================================

    # ── Clinical Infectious Diseases (CID / IDSA) ─────────────────────────────
    # IF ~20 — journal officiel IDSA. THE référence en infectiologie clinique :
    # guidelines IDSA (VIH, endocardite, méningite, candidose, aspergilllose),
    # essais pivots toutes infections, données de registre US/EU. Volume élevé.
    {
        "source": "pubmed_cid",
        "journal_term": f'"Clin Infect Dis"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Infectious Diseases (IDSA) — guidelines IDSA + RCTs toutes infections (IF ~20)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── Lancet Infectious Diseases ────────────────────────────────────────────
    # IF ~36 — plus haut IF infectiologie. Publie les grands RCTs practice-changing
    # (VIH injectables LA ATLAS/FLAIR, tuberculose BPaL, sepsis, paludisme vaccin),
    # guidelines ESCMID, méta-analyses réseau. Volume faible, très sélectif.
    {
        "source": "pubmed_lancet_infect_dis",
        "journal_term": f'"Lancet Infect Dis"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Infectious Diseases — RCTs VIH/TB/sepsis/paludisme practice-changing (IF ~36)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── Journal of Infectious Diseases ────────────────────────────────────────
    # IF ~7 — journal IDSA (historique). Publie les essais cliniques randomisés
    # sur VIH, hépatites virales, infections bactériennes sévères, vaccination,
    # immunologie anti-infectieuse. Forte couverture virologie et immunité.
    {
        "source": "pubmed_j_infect_dis",
        "journal_term": f'"J Infect Dis"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Infectious Diseases (IDSA) — VIH, hépatites, infections bactériennes (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── AIDS (IAS / Lippincott) ───────────────────────────────────────────────
    # IF ~5 — journal officiel IAS (International AIDS Society). THE référence
    # VIH/sida : essais ART, résistances, stratégies switch, PrEP, comorbidités
    # (cardiovasculaire, rénale, osseuse, cancer), études de cohorte (COHERE,
    # NA-ACCORD, CASCADE). Inclut guidelines BHIVA/EACS/IAS.
    {
        "source": "pubmed_aids_journal",
        "journal_term": f'"AIDS"[Journal] AND {_PT_FILTER}',
        "label": "AIDS (IAS) — ART, PrEP, résistances, comorbidités VIH (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── Antimicrobial Agents and Chemotherapy (AAC / ASM) ────────────────────
    # IF ~5 — journal officiel ASM. THE référence pharmacologie anti-infectieuse :
    # PK/PD antibiotiques, CMI, mécanismes de résistance, études cliniques sur
    # nouvelles molécules (CAZ-AVI, ATM-AVI, cefidérocol), antifongiques (olorofim).
    # Filtre _PT_FILTER strict : évite les seules études in vitro/animal.
    {
        "source": "pubmed_aac",
        "journal_term": f'"Antimicrob Agents Chemother"[Journal] AND {_PT_FILTER}',
        "label": "Antimicrobial Agents & Chemotherapy (ASM) — nouvelles molécules, PK/PD (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── Journal of Antimicrobial Chemotherapy (JAC / BSAC) ───────────────────
    # IF ~6 — journal officiel BSAC (British Society for Antimicrobial Chemotherapy).
    # Publie les essais cliniques et études de cohorte sur antibiothérapie optimisée,
    # BMR (BLSE, KPC, MBL), données épidémiologiques européennes de résistance
    # (EUCAST), pharmacovigilance antibiotiques.
    {
        "source": "pubmed_jac",
        "journal_term": f'"J Antimicrob Chemother"[Journal] AND {_PT_FILTER}',
        "label": "J Antimicrobial Chemotherapy (BSAC) — BMR, KPC/MBL, EUCAST EU (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── Emerging Infectious Diseases (EID / CDC) ──────────────────────────────
    # IF ~12 — journal officiel CDC. Publie les alertes épidémiologiques (nouvelles
    # espèces, épidémies émergentes), études sur agents pathogènes émergents
    # (arboviroses, zoonoses, variants SARS-CoV-2, mpox), données de surveillance
    # sentinelle. Essentiel pour la veille infectiologique.
    # _PT_OR_TITLE pour capter les études de surveillance (pas toujours labellisées RCT).
    {
        "source": "pubmed_emerg_infect_dis",
        "journal_term": f'"Emerg Infect Dis"[Journal] AND {_PT_OR_TITLE}',
        "label": "Emerging Infectious Diseases (CDC) — épidémies émergentes, zoonoses, mpox (IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── International Journal of Antimicrobial Agents (IJAA) ─────────────────
    # IF ~7 — journal ESCMID. Publie les essais cliniques sur nouveaux antibiotiques
    # (cefidérocol, omadacycline, télavancine), données cliniques sur BMR en
    # contexte européen, guidelines ESCMID sur antibiothérapie des infections sévères.
    {
        "source": "pubmed_ijaa",
        "journal_term": f'"Int J Antimicrob Agents"[Journal] AND {_PT_FILTER}',
        "label": "Int J Antimicrobial Agents (ESCMID) — cefidérocol, BMR, guidelines ESCMID (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── Journal of Infection ──────────────────────────────────────────────────
    # IF ~18 — journal BSID. Publie des études épidémiologiques et cliniques sur
    # infections bactériennes (pneumococcies, méningites, légionellose), infections
    # virales communautaires (grippe, VRS, COVID-19), et infections importées
    # (dengue, chikungunya, infections à Clostridium difficile). Volume modéré.
    {
        "source": "pubmed_j_infect",
        "journal_term": f'"J Infect"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Infection (BSID) — infections bactériennes, virales, importées (IF ~18)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 6,
    },

    # ── HIV Medicine (BHIVA) ──────────────────────────────────────────────────
    # IF ~4 — journal officiel BHIVA (British HIV Association). Publie les guidelines
    # BHIVA (ART, PrEP, comorbidités, grossesse VIH+), données de vie réelle
    # cohortes UK (CHIC, INSIGHT), essais switch ART. Forte pertinence clinique
    # en pratique VIH européenne.
    # _PT_OR_TITLE pour capter les guidelines BHIVA.
    {
        "source": "pubmed_hiv_med",
        "journal_term": f'"HIV Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "HIV Medicine (BHIVA) — guidelines BHIVA, switch ART, cohortes UK (IF ~4)",
        "source_type": "recommandation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ── Euro Surveillance (ECDC) ──────────────────────────────────────────────
    # IF ~11 — journal officiel ECDC (European Centre for Disease Prevention and
    # Control). Publie les données de surveillance épidémiologique EU (résistances,
    # épidémies, souches émergentes), les avis techniques ECDC, les études de
    # terrain (field investigations). Réglementaire européen pour la veille.
    # _PT_OR_TITLE pour capter les études de surveillance ECDC.
    {
        "source": "pubmed_euro_surveill",
        "journal_term": f'"Euro Surveill"[Journal] AND {_PT_OR_TITLE}',
        "label": "Euro Surveillance (ECDC) — épidémiologie EU, résistances, surveillance sentinelle (IF ~11)",
        "source_type": "recommandation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ── Mycoses ───────────────────────────────────────────────────────────────
    # IF ~4 — journal Wiley. THE référence mycologie clinique : essais sur antifongiques
    # (échinocandines, azolés, ibrexafungerp, olorofim), candidoses invasives,
    # aspergillose, mucormycose, cryptococcose, dermatophyties profondes.
    # Guidelines ESCMID/ISHAM sur infections fongiques.
    {
        "source": "pubmed_mycoses",
        "journal_term": f'"Mycoses"[Journal] AND {_PT_OR_TITLE}',
        "label": "Mycoses — antifongiques, candidoses invasives, aspergillose, mucormycose (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ── Médecine et Maladies Infectieuses (SPILF) ─────────────────────────────
    # IF ~4 — journal officiel SPILF (Société de Pathologie Infectieuse de Langue
    # Française). THE source réglementaire française en infectiologie : conférences
    # de consensus SPILF/HAS, recommandations de pratique (antibiothérapie en ville,
    # IST, endocardite, infections urinaires, infections cutanées). Obligatoire pour
    # la pratique française.
    # _PT_OR_TITLE pour capturer les recommandations SPILF.
    {
        "source": "pubmed_med_mal_infect",
        "journal_term": f'"Med Mal Infect"[Journal] AND {_PT_OR_TITLE}',
        "label": "Médecine et Maladies Infectieuses (SPILF) — recommandations SPILF/HAS françaises (IF ~4)",
        "source_type": "recommandation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ── Infection (Springer) ──────────────────────────────────────────────────
    # IF ~5 — journal Springer international. Publie les essais cliniques et études
    # de cohorte sur infections bactériennes communautaires et hospitalières,
    # antibiothérapie probabiliste, infections de prothèses ostéo-articulaires (IOA),
    # endocardites. Forte couverture infections ostéo-articulaires.
    {
        "source": "pubmed_infection",
        "journal_term": f'"Infection"[Journal] AND {_PT_FILTER}',
        "label": "Infection (Springer) — IOA, endocardite, infections communautaires (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ── European Journal of Clinical Microbiology & Infectious Diseases ────────
    # IF ~4 — journal ESCMID/Springer. Publie des études cliniques et microbiologiques
    # sur résistances bactériennes (phénotypes BLSE/KPC/MBL), diagnostic rapide
    # (PCR, MALDI-TOF), antibiothérapie en vie réelle, comparaisons de schémas
    # antibiotiques dans les infections à germes résistants.
    {
        "source": "pubmed_eur_j_clin_microbiol",
        "journal_term": f'"Eur J Clin Microbiol Infect Dis"[Journal] AND {_PT_FILTER}',
        "label": "Eur J Clin Microbiology & Infect Dis (ESCMID) — BMR, diagnostic rapide (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ── PLoS Neglected Tropical Diseases ─────────────────────────────────────
    # IF ~4 — journal PLoS. THE référence maladies tropicales négligées : paludisme
    # (traitements, résistances artémisinine), dengue, chikungunya, filarioses,
    # leishmaniose, trypanosomiase, mycétomes. Forte pertinence pour les patients
    # rapatriés/voyageurs et médecine tropicale.
    {
        "source": "pubmed_plos_ntd",
        "journal_term": f'"PLoS Negl Trop Dis"[Journal] AND {_PT_FILTER}',
        "label": "PLoS Neglected Tropical Diseases — paludisme, dengue, leishmaniose, NTDs (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # INFIRMIERS ET INFIRMIÈRES — PRATIQUE ET SCIENCES INFIRMIÈRES
    # 16 journaux couvrant : pratique infirmière fondée sur les preuves (EBN),
    # plaies et cicatrisation (escarres, plaies chroniques, pansements modernes),
    # douleur et soins palliatifs, éducation thérapeutique (ETP), infections
    # nosocomiales/prévention (hygiène des mains, cathéters, soins invasifs),
    # soins critiques infirmiers (réanimation, urgences), formation infirmière,
    # management des équipes soignantes, oncologie infirmière.
    # Sources couvrent les guidelines internationales applicables en France :
    # EPUAP/NPIAP (escarres), EWMA (plaies), WOCN (stomies), SFAP (palliatif).
    # ==========================================================================

    # ── International Journal of Nursing Studies ──────────────────────────────
    # IF ~8 — plus haut IF sciences infirmières. Publie RCTs et méta-analyses
    # sur pratiques infirmières fondées sur les preuves : gestion cathéters,
    # prévention escarres, observance, transitions hôpital-domicile.
    {
        "source": "pubmed_int_j_nurs_stud",
        "journal_term": f'"Int J Nurs Stud"[Journal] AND {_PT_FILTER}',
        "label": "Int J Nursing Studies — RCTs pratiques infirmières EBN (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 6,
    },

    # ── Journal of Advanced Nursing ───────────────────────────────────────────
    # IF ~4 — journal Wiley. Publie méta-analyses, essais cliniques et revues
    # systématiques sur pratiques infirmières avancées, éducation thérapeutique,
    # coordination des soins, rôles étendus de l'infirmier (IPA, IPDE).
    {
        "source": "pubmed_j_adv_nurs",
        "journal_term": f'"J Adv Nurs"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Advanced Nursing — pratiques avancées, ETP, coordination soins (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 6,
    },

    # ── Journal of Clinical Nursing ───────────────────────────────────────────
    # IF ~4 — journal Wiley. Publie des essais cliniques et revues systématiques
    # sur soins infirmiers cliniques : plaies, cathéters veineux, soins palliatifs,
    # évaluation de la douleur, sécurité des soins, prélèvements.
    {
        "source": "pubmed_j_clin_nurs",
        "journal_term": f'"J Clin Nurs"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Clinical Nursing — soins cliniques, plaies, sécurité des soins (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 6,
    },

    # ── Nurse Education Today ─────────────────────────────────────────────────
    # IF ~4 — journal Elsevier formation infirmière. Publie des études sur
    # simulation en soins infirmiers, e-learning, compétences techniques et
    # relationnelles, évaluation des programmes de formation. Retenir les essais
    # sur méthodes pédagogiques validées (simulation haute-fidélité, débriefing).
    {
        "source": "pubmed_nurse_educ_today",
        "journal_term": f'"Nurse Educ Today"[Journal] AND {_PT_FILTER}',
        "label": "Nurse Education Today — simulation, compétences, formation infirmière (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Nursing Research ──────────────────────────────────────────────────────
    # IF ~3 — journal Wolters Kluwer (historique). Publie des essais cliniques
    # randomisés sur pratiques infirmières fondées sur les preuves : évaluation
    # de la douleur, gestion du stress des soignants, soins oncologiques infirmiers.
    {
        "source": "pubmed_nurs_res",
        "journal_term": f'"Nurs Res"[Journal] AND {_PT_FILTER}',
        "label": "Nursing Research — RCTs soins infirmiers fondés sur les preuves (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Worldviews on Evidence-Based Nursing ──────────────────────────────────
    # IF ~3 — journal Sigma Theta Tau / Wiley. THE référence pratique infirmière
    # fondée sur les preuves : implémentation des protocoles EBN en pratique,
    # barrières/facilitateurs à l'adoption des recommandations, changements
    # organisationnels. _PT_OR_TITLE pour les éditoriaux de position.
    {
        "source": "pubmed_worldviews_ebn",
        "journal_term": f'"Worldviews Evid Based Nurs"[Journal] AND {_PT_OR_TITLE}',
        "label": "Worldviews Evidence-Based Nursing — implémentation EBN, protocoles (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── International Wound Journal ───────────────────────────────────────────
    # IF ~3 — journal Wiley plaies chroniques. Publie les RCTs et méta-analyses sur
    # pansements modernes (hydrocolloïde, hydrogel, mousse, PHMB, argent), cicatrice
    # complexe, pied diabétique, escarres, thérapie par pression négative (VAC).
    # Forte pertinence pour les infirmiers en plaies et cicatrisation (IPDE).
    {
        "source": "pubmed_int_wound_j",
        "journal_term": f'"Int Wound J"[Journal] AND {_PT_FILTER}',
        "label": "International Wound Journal — pansements, plaies chroniques, pied diabétique (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Journal of Wound Care ─────────────────────────────────────────────────
    # IF ~2 — journal MAG Online/EWMA. Publie des études cliniques et guidelines
    # EWMA/EPUAP/NPIAP sur plaies chroniques (escarres, ulcères veineux/artériels,
    # pied diabétique), préparation du lit de la plaie (TIME framework), détersion,
    # compression. _PT_OR_TITLE pour les position papers EWMA.
    {
        "source": "pubmed_j_wound_care",
        "journal_term": f'"J Wound Care"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Wound Care (EWMA) — escarres, ulcères, TIME framework, EPUAP (IF ~2)",
        "source_type": "recommandation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Wound Repair and Regeneration ────────────────────────────────────────
    # IF ~4 — journal Wiley/Wound Healing Society. Publie des essais cliniques sur
    # cicatrisation et régénération tissulaire : PRP, facteurs de croissance, greffes
    # de peau, cellules souches en plaies chroniques. Complémentaire de Int Wound J.
    {
        "source": "pubmed_wound_repair",
        "journal_term": f'"Wound Repair Regen"[Journal] AND {_PT_FILTER}',
        "label": "Wound Repair & Regeneration — PRP, facteurs croissance, cicatrisation (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Pain Management Nursing ───────────────────────────────────────────────
    # IF ~2 — journal ASPMN (American Society for Pain Management Nursing). Publie
    # des études sur évaluation et prise en charge infirmière de la douleur aiguë et
    # chronique : protocoles analgésiques, échelles (EVA, DN4, DOLOPLUS, EVENDOL),
    # douleurs procédurales (pansements, ponctions), MEOPA, opioïdes.
    {
        "source": "pubmed_pain_manag_nurs",
        "journal_term": f'"Pain Manag Nurs"[Journal] AND {_PT_OR_TITLE}',
        "label": "Pain Management Nursing — douleur, DOLOPLUS/EVA, MEOPA, opioïdes (IF ~2)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Applied Nursing Research ──────────────────────────────────────────────
    # IF ~2 — journal Elsevier pratique clinique infirmière. Publie des études
    # d'implémentation de protocoles infirmiers, études avant/après sur la sécurité
    # des soins, évaluation de checklists (HAS, OMS), prévention des erreurs
    # médicamenteuses, traçabilité des soins.
    {
        "source": "pubmed_appl_nurs_res",
        "journal_term": f'"Appl Nurs Res"[Journal] AND {_PT_OR_TITLE}',
        "label": "Applied Nursing Research — implémentation protocoles, sécurité soins (IF ~2)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Journal of Nursing Management ─────────────────────────────────────────
    # IF ~3 — journal Wiley. Publie des études sur organisation des soins infirmiers :
    # charge de travail (workload), ratios infirmier/patients (RATPAQ, RN4CAST),
    # burnout infirmier, turn-over, leadership infirmier, qualité des soins.
    {
        "source": "pubmed_j_nurs_manag",
        "journal_term": f'"J Nurs Manag"[Journal] AND {_PT_FILTER}',
        "label": "J Nursing Management — ratios IDE/patients, burnout, charge de travail (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── European Journal of Oncology Nursing ──────────────────────────────────
    # IF ~3 — journal Elsevier/EONS. Publie des études sur soins infirmiers en
    # oncologie : gestion des effets secondaires des chimiothérapies (nausées/
    # vomissements, mucites, neutropénie), soins de support, éducation thérapeutique
    # en onco, stomies et prise en charge infirmière post-chirurgie carcinologique.
    {
        "source": "pubmed_eur_j_oncol_nurs",
        "journal_term": f'"Eur J Oncol Nurs"[Journal] AND {_PT_FILTER}',
        "label": "Eur J Oncology Nursing (EONS) — chimio effects, stomies, soins onco (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Intensive and Critical Care Nursing ───────────────────────────────────
    # IF ~3 — journal Elsevier soins critiques infirmiers. Publie des études sur
    # pratiques infirmières en réanimation et soins intensifs : prévention PAVM
    # (position demi-assise, hygiène buccale chlorhexidine), délire (CAM-ICU,
    # mobilisation précoce), gestion des cathéters centraux, soins de confort.
    {
        "source": "pubmed_intensive_crit_care_nurs",
        "journal_term": f'"Intensive Crit Care Nurs"[Journal] AND {_PT_FILTER}',
        "label": "Intensive & Critical Care Nursing — PAVM, délire REA, mobilisation précoce (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Journal of Nursing Scholarship ───────────────────────────────────────
    # IF ~3 — journal Sigma Theta Tau. Publie des études cliniques multicentriques
    # sur pratiques infirmières fondées sur les preuves, résultats de santé liés
    # aux interventions infirmières, leadership et innovation en sciences infirmières.
    {
        "source": "pubmed_j_nurs_scholarsh",
        "journal_term": f'"J Nurs Scholarsh"[Journal] AND {_PT_FILTER}',
        "label": "J Nursing Scholarship (Sigma) — interventions infirmières, résultats santé (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ── Nursing Open (Wiley open access) ─────────────────────────────────────
    # IF ~2 — journal Wiley open access. Publie des essais cliniques et revues
    # systématiques sur soins infirmiers dans toutes spécialités, avec forte
    # proportion d'études multicentriques asiatiques et européennes. Volume élevé.
    {
        "source": "pubmed_nurs_open",
        "journal_term": f'"Nurs Open"[Journal] AND {_PT_FILTER}',
        "label": "Nursing Open (Wiley OA) — essais multicentriques soins infirmiers (IF ~2)",
        "source_type": "innovation",
        "specialty_hint": "infirmiers",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # KINÉSITHÉRAPIE ET RÉÉDUCATION FONCTIONNELLE
    # 16 journaux couvrant : rééducation musculo-squelettique (lombalgie, cervicalgie,
    # tendinopathies, entorses, syndromes d'accrochage, post-chirurgie), neurologique
    # (AVC/CIMT/robot, Parkinson LSVT, SEP, blessés médullaires), cardio-respiratoire
    # (réhabilitation BPCO/insuffisance cardiaque, drainage bronchique, mucoviscidose),
    # périnéal (incontinence urinaire, périnée), analyse du mouvement (Gait & Posture),
    # réhabilitation améliorée après chirurgie (ERAS). Réglementaire : HAS, SOFMER,
    # WCPT/KNGF guidelines, Cochrane MSK/Neuro/Resp.
    # ==========================================================================

    # ── Physical Therapy (APTA) ───────────────────────────────────────────────
    # IF ~4 — journal officiel APTA (American Physical Therapy Association). THE
    # référence kinésithérapie mondiale : RCTs et revues systématiques sur toutes
    # les spécialités kinés (MSK, neuro, cardio-resp), guidelines APTA, études
    # sur l'examen clinique et les tests diagnostiques.
    {
        "source": "pubmed_phys_ther",
        "journal_term": f'"Phys Ther"[Journal] AND {_PT_FILTER}',
        "label": "Physical Therapy (APTA) — RCTs + guidelines toutes spécialités kiné (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── Journal of Orthopaedic & Sports Physical Therapy (JOSPT) ─────────────
    # IF ~7 — THE référence kiné musculo-squelettique et sportive. Publie les RCTs
    # et revues systématiques sur lombalgie, cervicalgie, épaule, hanche, genou,
    # cheville. Inclut les Clinical Practice Guidelines JOSPT (piliers evidence-based).
    # _PT_OR_TITLE pour capter les CPGs JOSPT.
    {
        "source": "pubmed_jospt",
        "journal_term": f'"J Orthop Sports Phys Ther"[Journal] AND {_PT_OR_TITLE}',
        "label": "JOSPT — RCTs + Clinical Practice Guidelines MSK et sportive (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── Journal of Physiotherapy (APA) ────────────────────────────────────────
    # IF ~8 — journal officiel APA (Australian Physiotherapy Association). Plus haut
    # IF physiothérapie généraliste. Publie RCTs de haute qualité, revues systématiques
    # et méta-analyses sur toutes spécialités kiné avec focus australien/international.
    {
        "source": "pubmed_j_physiother",
        "journal_term": f'"J Physiother"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Physiotherapy (APA) — plus haut IF kiné généraliste (IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── British Journal of Sports Medicine (BJSM) ────────────────────────────
    # IF ~18 — journal BMJ spécialisé sport et MSK. Publie les RCTs, méta-analyses
    # et guidelines sur tendinopathies, blessures sportives, retour au sport, running,
    # réhabilitation MSK haute performance. Très influent pour les kinés du sport.
    {
        "source": "pubmed_br_j_sports_med_kine",
        "journal_term": f'"Br J Sports Med"[Journal] AND {_PT_FILTER}',
        "label": "British J Sports Medicine — tendinopathies, blessures sportives, retour sport (IF ~18)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── Clinical Rehabilitation ───────────────────────────────────────────────
    # IF ~4 — journal SAGE. Publie des RCTs multicentriques sur toutes les modalités
    # de rééducation : AVC, traumatismes crâniens, douleur chronique, polyarthrite,
    # amputations, réhabilitation post-chirurgie orthopédique. Volume élevé.
    {
        "source": "pubmed_clin_rehabil",
        "journal_term": f'"Clin Rehabil"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Rehabilitation — RCTs AVC, douleur chronique, post-chir ortho (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── Archives of Physical Medicine and Rehabilitation (APMR) ──────────────
    # IF ~4 — journal officiel AAPM&R. THE référence médecine physique et réadaptation
    # (MPR). Publie RCTs et revues sur rééducation neurologique (AVC, blessés
    # médullaires, TCC), réhabilitation musculo-squelettique, douleur chronique,
    # évaluation fonctionnelle (FIM, BI). Volume élevé.
    {
        "source": "pubmed_arch_phys_med_rehabil",
        "journal_term": f'"Arch Phys Med Rehabil"[Journal] AND {_PT_FILTER}',
        "label": "Archives of Physical Medicine & Rehabilitation — MPR, AVC, blessés méd. (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── Disability and Rehabilitation ────────────────────────────────────────
    # IF ~3 — journal Taylor & Francis. Publie des études sur handicap et réadaptation :
    # retour au travail, réinsertion sociale, incapacité chronique (lombalgie, SEP,
    # polyarthrite), modèle ICF/OMS en rééducation, interventions basées sur ICF.
    {
        "source": "pubmed_disabil_rehabil",
        "journal_term": f'"Disabil Rehabil"[Journal] AND {_PT_FILTER}',
        "label": "Disability & Rehabilitation — ICF, retour travail, incapacité chronique (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── Journal of Rehabilitation Medicine (UEMS/EAR) ─────────────────────────
    # IF ~3 — journal officiel UEMS/EAR (European Academy of Rehabilitation Medicine).
    # THE référence rééducation européenne : RCTs multicentriques EU, guidelines
    # UEMS, études fonctionnelles post-AVC, post-orthopédie, données de registres
    # européens de rééducation. Pertinent pour la pratique française.
    {
        "source": "pubmed_j_rehabil_med",
        "journal_term": f'"J Rehabil Med"[Journal] AND {_PT_FILTER}',
        "label": "J Rehabilitation Medicine (UEMS/EAR) — rééducation EU, guidelines UEMS (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── BMC Musculoskeletal Disorders ─────────────────────────────────────────
    # IF ~3 — journal BioMed Central open access. Publie des RCTs, revues
    # systématiques et études de cohorte sur pathologies ostéo-articulaires :
    # lombalgie, arthrose, arthroplastie, ostéoporose, tendinopathies, post-chirurgie
    # orthopédique. Volume élevé, accès libre, forte représentation internationale.
    {
        "source": "pubmed_bmc_musculoskelet",
        "journal_term": f'"BMC Musculoskelet Disord"[Journal] AND {_PT_FILTER}',
        "label": "BMC Musculoskeletal Disorders — lombalgie, arthrose, tendinopathies OA (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── Journal of Cardiopulmonary Rehabilitation and Prevention ──────────────
    # IF ~3 — journal officiel AACVPR. Publie les RCTs et guidelines sur
    # réhabilitation cardiaque (post-IDM, insuffisance cardiaque, post-chirurgie
    # cardiaque) et respiratoire (BPCO, fibrose pulmonaire, mucoviscidose).
    # Essentiel pour les kinés de réhabilitation cardio-respiratoire.
    {
        "source": "pubmed_j_cardiopulm_rehabil",
        "journal_term": f'"J Cardiopulm Rehabil Prev"[Journal] AND {_PT_FILTER}',
        "label": "J Cardiopulmonary Rehab & Prevention (AACVPR) — réhab cardiaque + BPCO (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── Neurorehabilitation and Neural Repair ─────────────────────────────────
    # IF ~5 — journal SAGE neurologie/rééducation. THE référence rééducation
    # neurologique : AVC (TCI/CIMT, stimulation TMS/tDCS, exosquelette, robot,
    # réalité virtuelle), blessés médullaires (FES), Parkinson, SEP.
    # Retenir les RCTs sur nouvelles technologies de rééducation.
    {
        "source": "pubmed_neurorehabil_neural_repair",
        "journal_term": f'"Neurorehabil Neural Repair"[Journal] AND {_PT_FILTER}',
        "label": "Neurorehabilitation & Neural Repair — AVC/CIMT/robot/TMS, rééd neurologique (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── Journal of NeuroEngineering and Rehabilitation ────────────────────────
    # IF ~5 — journal BioMed Central. Publie les essais sur technologies de
    # rééducation neuro : exosquelettes (Ekso, Lokomat), interfaces cerveau-machine
    # (BCI), stimulation électrique fonctionnelle (FES), réalité virtuelle, robotique.
    # Essentiels pour les kinés en haute technologie neurologique.
    {
        "source": "pubmed_j_neuroeng_rehabil",
        "journal_term": f'"J Neuroeng Rehabil"[Journal] AND {_PT_FILTER}',
        "label": "J Neuroengineering & Rehabilitation — exosquelettes, BCI, FES, réalité virtuelle (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── Annals of Physical and Rehabilitation Medicine (SOFMER) ───────────────
    # IF ~6 — journal officiel SOFMER (Société Française de Médecine Physique et
    # Réadaptation). THE source réglementaire française en MPR : Conférences
    # d'Experts SOFMER, recommandations HAS/SOFMER (rééducation AVC, lombalgie,
    # rééducation respiratoire), études de registres français PMSI-MPR.
    # _PT_OR_TITLE pour capter les recommandations SOFMER.
    {
        "source": "pubmed_ann_phys_rehabil_med",
        "journal_term": f'"Ann Phys Rehabil Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals of Physical & Rehab Med (SOFMER) — recommandations SOFMER/HAS françaises (IF ~6)",
        "source_type": "recommandation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 6,
    },

    # ── European Journal of Physical and Rehabilitation Medicine ──────────────
    # IF ~4 — journal officiel SIMFER/ESPRM (sociétés européennes MPR). Publie
    # les RCTs multicentriques et guidelines européens de rééducation : ESPRM
    # guidelines AVC, recommandations spasticiité, réhabilitation MSK, douleur
    # chronique. Complémentaire d'Ann Phys Rehabil Med pour la pratique européenne.
    # _PT_OR_TITLE pour les guidelines ESPRM.
    {
        "source": "pubmed_eur_j_phys_rehabil_med",
        "journal_term": f'"Eur J Phys Rehabil Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Eur J Physical & Rehab Medicine (ESPRM) — guidelines EU rééducation (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── Gait & Posture ────────────────────────────────────────────────────────
    # IF ~3 — journal Elsevier analyse du mouvement. Publie des études cliniques sur
    # marche, équilibre et posture : analyse cinématique/cinétique, orthèses de marche,
    # analyse de marche post-AVC/Parkinson/PTH/PTG, test 6 minutes marche, TUG, BBS.
    # Essentiel pour les kinés spécialisés en analyse du mouvement et bilan d'appareillage.
    {
        "source": "pubmed_gait_posture",
        "journal_term": f'"Gait Posture"[Journal] AND {_PT_FILTER}',
        "label": "Gait & Posture — analyse marche, équilibre, orthèses, post-PTH/PTG/AVC (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ── Musculoskeletal Science and Practice ──────────────────────────────────
    # IF ~3 — journal ex-Manual Therapy (fusionné). THE référence thérapie manuelle
    # et MSK : raisonnement clinique, thérapie manuelle orthopédique (Maitland, McKenzie,
    # Mulligan), psychologie de la douleur (modèle biopsychosocial), exercices
    # thérapeutiques. Très référencé pour les kinés MSK et la lombalgie.
    {
        "source": "pubmed_musculoskelet_sci_pract",
        "journal_term": f'"Musculoskelet Sci Pract"[Journal] AND {_PT_FILTER}',
        "label": "Musculoskeletal Science & Practice — thérapie manuelle, McKenzie, biopsychosocial (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "kinesitherapie",
        "min_score_hint": 7,
    },

    # ==========================================================================
    # MÉDECINE GÉNÉRALE ET SOINS PRIMAIRES
    # 16 journaux couvrant : HTA (ESC/ESH 2023, cibles, traitements), diabète T2
    # (ADA/EASD 2023, GLP-1/iSGLT2 en soins primaires), prévention CV (SCORE2,
    # statines, aspirine), dépistage organisé (sein/CCR/col HPV/poumon), vaccination
    # (calendrier France 2024), asthme (GINA 2023), BPCO (GOLD 2024), santé mentale
    # (dépression, anxiété, burn-out), antibiothérapie ville (SPILF/HAS 2021 :
    # angine TDR, cystite fosfomycine), addictologie (tabac, alcool), lombalgie,
    # activité physique sur ordonnance (APS), soins non programmés, télémédecine.
    # ==========================================================================

    # ── Journal of General Internal Medicine (SGIM) ───────────────────────────
    # IF ~6 — journal officiel SGIM (Society of General Internal Medicine). Publie
    # RCTs et méta-analyses sur gestion des maladies chroniques en soins primaires
    # (HTA, DT2, ICC, BPCO, dépression, polypharmacie), qualité et sécurité des soins.
    {
        "source": "pubmed_j_gen_intern_med",
        "journal_term": f'"J Gen Intern Med"[Journal] AND {_PT_FILTER}',
        "label": "J General Internal Medicine (SGIM) — maladies chroniques soins primaires (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── Journal of Hypertension (ESH) ─────────────────────────────────────────
    # IF ~8 — journal officiel ESH (European Society of Hypertension). THE référence
    # HTA en médecine générale : guidelines ESC/ESH 2023 (cibles, traitements,
    # automesure tensionnelle, HTA résistante), RCTs sur nouveaux antihypertenseurs,
    # études de cohorte sur complications de l'HTA.
    # _PT_OR_TITLE pour capter les guidelines ESH.
    {
        "source": "pubmed_j_hypertens",
        "journal_term": f'"J Hypertens"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Hypertension (ESH) — guidelines ESH 2023, cibles, traitements (IF ~8)",
        "source_type": "recommandation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── Preventive Medicine ───────────────────────────────────────────────────
    # IF ~5 — journal Elsevier. Publie des études sur prévention primaire et secondaire :
    # dépistages organisés (cancer sein, CCR, col, poumon), vaccination, modes de vie
    # (activité physique, alimentation), prévention des maladies chroniques. Très
    # pertinent pour la mission préventive du médecin généraliste.
    {
        "source": "pubmed_prev_med",
        "journal_term": f'"Prev Med"[Journal] AND {_PT_FILTER}',
        "label": "Preventive Medicine — dépistages, vaccination, prévention primaire (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── International Journal of Clinical Practice ────────────────────────────
    # IF ~3 — journal Wiley. Publie des études sur pratiques cliniques en médecine
    # générale et interne : gestion des comorbidités, interactions médicamenteuses,
    # observance, efficacité des traitements en conditions réelles (RWE).
    {
        "source": "pubmed_int_j_clin_pract",
        "journal_term": f'"Int J Clin Pract"[Journal] AND {_PT_FILTER}',
        "label": "Int J Clinical Practice — comorbidités, interactions, RWE en pratique (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── British Journal of General Practice (RCGP) ────────────────────────────
    # IF ~6 — journal officiel RCGP (Royal College of General Practitioners). THE
    # référence médecine générale UK/EU. Publie les RCTs en soins primaires, les
    # guidelines NICE (applicables en MG), les études de cohorte CPRD (NHS database),
    # études organisationnelles sur les soins primaires européens.
    # _PT_OR_TITLE pour capter les guidelines NICE publiées via BJGP.
    {
        "source": "pubmed_bjgp",
        "journal_term": f'"Br J Gen Pract"[Journal] AND {_PT_OR_TITLE}',
        "label": "British J General Practice (RCGP) — RCTs soins primaires UK, NICE, CPRD (IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── American Journal of Preventive Medicine ───────────────────────────────
    # IF ~5 — journal ACPM. Publie des études sur prévention clinique : dépistage
    # cancers, maladies cardiovasculaires, santé mentale, addictions (tabac, alcool),
    # inégalités de santé en soins primaires, interventions sur les déterminants sociaux.
    {
        "source": "pubmed_am_j_prev_med",
        "journal_term": f'"Am J Prev Med"[Journal] AND {_PT_FILTER}',
        "label": "American J Preventive Medicine — dépistages cancers, addictions, inégalités santé (IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── Canadian Medical Association Journal (CMAJ) ───────────────────────────
    # IF ~14 — journal officiel AMC (Association médicale canadienne). Publie des
    # guidelines de pratique clinique (CPG) couvrant tous les domaines de la médecine
    # générale et interne, des RCTs multicentriques canadiens/internationaux, et les
    # mises à jour de recommandations (HTA, DT2, dépistages, vaccinations).
    # _PT_OR_TITLE pour les CPGs CMAJ.
    {
        "source": "pubmed_cmaj",
        "journal_term": f'"CMAJ"[Journal] AND {_PT_OR_TITLE}',
        "label": "CMAJ — guidelines pratique clinique toutes spécialités MG (IF ~14)",
        "source_type": "recommandation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── Family Practice (Oxford) ──────────────────────────────────────────────
    # IF ~3 — journal Oxford University Press. Publie des études sur la pratique
    # des médecins généralistes : consultation (durée, communication, raisonnement
    # clinique), gestion des motifs fréquents (lombalgie, insomnie, fatigue),
    # études ethnographiques et qualitatives de soins primaires.
    {
        "source": "pubmed_fam_pract",
        "journal_term": f'"Fam Pract"[Journal] AND {_PT_FILTER}',
        "label": "Family Practice (Oxford) — consultation, motifs fréquents MG, RCTs (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── BMC Family Practice / BMC Primary Care ────────────────────────────────
    # IF ~3 — journal BioMed Central (renommé BMC Primary Care en 2022). Publie des
    # RCTs et cohortes sur soins primaires : management maladies chroniques, outils
    # diagnostiques en MG, organisations des soins, éducation thérapeutique.
    {
        "source": "pubmed_bmc_fam_pract",
        "journal_term": f'"BMC Fam Pract"[Journal] AND {_PT_FILTER}',
        "label": "BMC Family Practice (→ BMC Primary Care 2022) — RCTs soins primaires OA (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── Annals of Family Medicine ─────────────────────────────────────────────
    # IF ~7 — journal STFM (Society of Teachers of Family Medicine). Publie des
    # recherches originales sur la médecine de famille : maladies chroniques multiples
    # (multimorbidité), relation médecin-patient, continuité des soins, éducation
    # médicale en MG. Plus haut IF dédié médecine de famille.
    {
        "source": "pubmed_ann_fam_med",
        "journal_term": f'"Ann Fam Med"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Family Medicine (STFM) — plus haut IF médecine famille (IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── Primary Care Diabetes ─────────────────────────────────────────────────
    # IF ~3 — journal PCDSI. Publie des études sur la prise en charge du diabète
    # en soins primaires : autosurveillance glycémique, télémédecine diabète, mise
    # en route insuline en MG, éducation thérapeutique (ETP) DT2, pieds diabétiques.
    {
        "source": "pubmed_prim_care_diabetes",
        "journal_term": f'"Prim Care Diabetes"[Journal] AND {_PT_FILTER}',
        "label": "Primary Care Diabetes — DT2 soins primaires, autosurveillance, ETP (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── Journal of the American Board of Family Medicine ──────────────────────
    # IF ~3 — journal ABFM. Publie des études originales sur pratique clinique en
    # médecine de famille : tests diagnostiques en soins primaires, thérapeutiques
    # des maladies chroniques, formation médicale continue des généralistes.
    {
        "source": "pubmed_j_am_board_fam_med",
        "journal_term": f'"J Am Board Fam Med"[Journal] AND {_PT_FILTER}',
        "label": "J American Board of Family Medicine — tests diagnostiques, thérapeutiques MG (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── Scandinavian Journal of Primary Health Care ───────────────────────────
    # IF ~3 — journal NFGP (Nordic associations). Publie des études nordiques sur
    # soins primaires : registres nationaux scandinaves (CPRD-équivalents nordiques),
    # organisation des soins de ville, sécurité des soins ambulatoires, études sur
    # populations vieillissantes en médecine générale. Forte référence en Europe.
    {
        "source": "pubmed_scand_j_prim_health",
        "journal_term": f'"Scand J Prim Health Care"[Journal] AND {_PT_FILTER}',
        "label": "Scand J Primary Health Care — registres nordiques, soins primaires EU (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── BMC Primary Care (ex-BMC Family Practice, depuis 2022) ───────────────
    # IF ~3 — nouvelle dénomination BMC Family Practice depuis jan. 2022.
    # Publie les articles soumis après la transformation du journal, couvrant les
    # mêmes thématiques de soins primaires avec focus sur les nouvelles technologies
    # (télémédecine, IA en MG, outils numériques patients).
    {
        "source": "pubmed_bmc_prim_care",
        "journal_term": f'"BMC Prim Care"[Journal] AND {_PT_FILTER}',
        "label": "BMC Primary Care (ex-BMC Fam Pract post-2022) — télémédecine, IA en MG (IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── NPJ Primary Care Respiratory Medicine ─────────────────────────────────
    # IF ~4 — journal Nature Partner Journals. Publie des RCTs et revues sur gestion
    # des maladies respiratoires en soins primaires : asthme (GINA, spirométrie MG),
    # BPCO (GOLD, détection précoce), toux chronique, infections respiratoires
    # récurrentes. Retenir études sur outils diagnostiques accessibles au MG.
    {
        "source": "pubmed_npj_prim_care_respir",
        "journal_term": f'"NPJ Prim Care Respir Med"[Journal] AND {_PT_FILTER}',
        "label": "NPJ Primary Care Respiratory Med — asthme/BPCO/toux en soins primaires (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },

    # ── European Journal of General Practice (WONCA Europe) ───────────────────
    # IF ~3 — journal officiel WONCA Europe. THE référence médecine générale
    # européenne : guidelines WONCA (applicable en France), études sur organisation
    # des soins primaires en Europe, formation des médecins généralistes, gestion
    # des maladies chroniques en contexte européen. _PT_OR_TITLE pour les guidelines WONCA.
    {
        "source": "pubmed_eur_j_gen_pract",
        "journal_term": f'"Eur J Gen Pract"[Journal] AND {_PT_OR_TITLE}',
        "label": "Eur J General Practice (WONCA Europe) — guidelines WONCA, MG européenne (IF ~3)",
        "source_type": "recommandation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 7,
    },
    # ── JAMA Internal Medicine ────────────────────────────────────────────────
    # IF ~24 — journal AMA. Référence medecine-interne : maladies systémiques, guidelines ACP/AMA,
    # déprescription, polypharmacie, maladies chroniques, sécurité médicaments. Déplacé de
    # medecine-generale → medecine-interne (specialty_hint) — reste cross-spé via SOURCE_TO_TYPE.
    # _PT_OR_TITLE pour les guidelines AMA.
    {
        "source": "pubmed_jama_intern_med",
        "journal_term": f'"JAMA Intern Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "JAMA Internal Medicine (AMA, IF ~24) — maladies systémiques, déprescription, guidelines AMA",
        "source_type": "recommandation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },

    # ── BMJ (British Medical Journal) ─────────────────────────────────────────
    # IF ~107 — journal officiel BMA. Articles de recherche courts à fort impact,
    # revues cliniques pratiques (BMJ Learning), analyses politiques de santé.
    # Très lu par les médecins généralistes britanniques et européens. Publie les
    # guidelines NICE reformatées. _PT_OR_TITLE pour capter les guidelines publiées
    # sous format BMJ (NICE, BTS, SIGN...).
    {
        "source": "pubmed_bmj",
        "journal_term": f'"BMJ"[Journal] AND {_PT_OR_TITLE}',
        "label": "BMJ (British Medical Journal, IF ~107) — essais cliniques, revues pratiques, guidelines NICE",
        "source_type": "innovation",
        "specialty_hint": "medecine-generale",
        "min_score_hint": 6,
    },

    # ── Médecine interne ──────────────────────────────────────────────────────
    {
        "source": "pubmed_ann_intern_med",
        "journal_term": f'"Ann Intern Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals of Internal Medicine (ACP flagship, IF ~51) — guidelines ACP, essais phase 3",
        "source_type": "recommandation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_am_j_med",
        "journal_term": f'"Am J Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "American Journal of Medicine (Elsevier, IF ~4) — médecine interne générale",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_medicine_baltimore",
        "journal_term": f'"Medicine (Baltimore)"[Journal] AND {_PT_OR_TITLE}',
        "label": "Medicine (Baltimore) / Wolters Kluwer — revues systématiques et séries cliniques",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_bmc_med",
        "journal_term": f'"BMC Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "BMC Medicine (IF ~9) — essais cliniques et méta-analyses multimorbidité",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_j_clin_invest",
        "journal_term": f'"Eur J Clin Invest"[Journal] AND {_PT_OR_TITLE}',
        "label": "European J Clinical Investigation (EFIM, IF ~4) — pathologies systémiques, métabolisme",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_postgrad_med_j",
        "journal_term": f'"Postgrad Med J"[Journal] AND {_PT_OR_TITLE}',
        "label": "Postgraduate Medical Journal (RCP London, IF ~3) — formation continue, cas cliniques",
        "source_type": "recommandation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_intern_med",
        "journal_term": f'"J Intern Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Internal Medicine (Wiley/SNFMI-EFIM, IF ~8) — pathologies multisystémiques",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_j_intern_med",
        "journal_term": f'"Eur J Intern Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "European J Internal Medicine (EFIM flagship, IF ~5) — guidelines EFIM, revues européennes",
        "source_type": "recommandation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_mayo_clin_proc",
        "journal_term": f'"Mayo Clin Proc"[Journal] AND {_PT_OR_TITLE}',
        "label": "Mayo Clinic Proceedings (Elsevier, IF ~9) — revues cliniques pratiques, guidelines",
        "source_type": "recommandation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_intern_med_j",
        "journal_term": f'"Intern Med J"[Journal] AND {_PT_OR_TITLE}',
        "label": "Internal Medicine Journal (ANZMJ, IF ~2.5) — médecine interne Australasie",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_qjm",
        "journal_term": f'"QJM"[Journal] AND {_PT_OR_TITLE}',
        "label": "QJM: An International Journal of Medicine (Oxford, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_intern_emerg_med",
        "journal_term": f'"Intern Emerg Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Internal and Emergency Medicine (Springer, IF ~5) — SIMI, pathologies aiguës",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_am_j_med_sci",
        "journal_term": f'"Am J Med Sci"[Journal] AND {_PT_OR_TITLE}',
        "label": "American J Medical Sciences (SSCI, IF ~3) — pathologies systémiques, cas cliniques",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_swiss_med_wkly",
        "journal_term": f'"Swiss Med Wkly"[Journal] AND {_PT_OR_TITLE}',
        "label": "Swiss Medical Weekly (EMH, IF ~3) — médecine interne Europe francophone",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_j_investig_med",
        "journal_term": f'"J Investig Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Investigative Medicine (BMJ/AFMR, IF ~3) — pathologies métaboliques/systémiques",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_rev_med_interne",
        "journal_term": f'"Rev Med Interne"[Journal] AND {_PT_OR_TITLE}',
        "label": "Revue de Médecine Interne (SNFMI, IF ~2) — recommandations françaises médecine interne",
        "source_type": "recommandation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_eclinicalmedicine",
        "journal_term": f'"EClinicalMedicine"[Journal] AND {_PT_OR_TITLE}',
        "label": "EClinicalMedicine (Lancet group, IF ~15) — essais cliniques et méta-analyses multimorbidité",
        "source_type": "innovation",
        "specialty_hint": "medecine-interne",
        "min_score_hint": 6,
    },
    # ── Médecine physique et de réadaptation ──────────────────────────────────
    {
        "source": "pubmed_pm_r",
        "journal_term": f'"PM R"[Journal] AND {_PT_FILTER}',
        "label": "PM&R — Journal of Injury, Function, and Rehabilitation (AAPM&R, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_spinal_cord",
        "journal_term": f'"Spinal Cord"[Journal] AND {_PT_FILTER}',
        "label": "Spinal Cord (ISCoS / Nature, IF ~3) — lésions médullaires, rééducation SCI",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_brain_inj",
        "journal_term": f'"Brain Inj"[Journal] AND {_PT_FILTER}',
        "label": "Brain Injury (Taylor & Francis, IF ~2) — TBI/ABI, rééducation neurologique",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_top_stroke_rehabil",
        "journal_term": f'"Top Stroke Rehabil"[Journal] AND {_PT_OR_TITLE}',
        "label": "Topics in Stroke Rehabilitation (Taylor & Francis, IF ~3) — rééducation post-AVC",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_head_trauma_rehabil",
        "journal_term": f'"J Head Trauma Rehabil"[Journal] AND {_PT_FILTER}',
        "label": "J Head Trauma Rehabilitation (Wolters Kluwer, IF ~4) — TBI, rééducation cognitive",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_int_j_rehabil_res",
        "journal_term": f'"Int J Rehabil Res"[Journal] AND {_PT_FILTER}',
        "label": "Int J Rehabilitation Research (Wolters Kluwer, IF ~2) — réhabilitation générale",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_neuropsychol_rehabil",
        "journal_term": f'"Neuropsychol Rehabil"[Journal] AND {_PT_FILTER}',
        "label": "Neuropsychological Rehabilitation (Taylor & Francis, IF ~4) — TBI, AVC, rééducation cognitive",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_prosthet_orthot_int",
        "journal_term": f'"Prosthet Orthot Int"[Journal] AND {_PT_FILTER}',
        "label": "Prosthetics & Orthotics International (ISPO, IF ~2) — appareillage, amputations",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_spinal_cord_med",
        "journal_term": f'"J Spinal Cord Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "J Spinal Cord Medicine (ISCoS affiliate, IF ~2) — SCI, rééducation médullaire",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_pain",
        "journal_term": f'"Pain"[Journal] AND {_PT_FILTER}',
        "label": "Pain (IASP flagship, IF ~9) — douleur chronique, douleur neuropathique",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_eur_j_pain",
        "journal_term": f'"Eur J Pain"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Pain (EFIC, IF ~4) — douleur chronique, Europe",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_pain_med",
        "journal_term": f'"Pain Med"[Journal] AND {_PT_FILTER}',
        "label": "Pain Medicine (AAPM&R / Oxford, IF ~3) — douleur interventionnelle, MPR",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_mult_scler",
        "journal_term": f'"Mult Scler"[Journal] AND {_PT_FILTER}',
        "label": "Multiple Sclerosis Journal (ECTRIMS / SAGE, IF ~5) — SEP, rééducation neurologique",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_mult_scler_relat_disord",
        "journal_term": f'"Mult Scler Relat Disord"[Journal] AND {_PT_FILTER}',
        "label": "Multiple Sclerosis and Related Disorders (Elsevier, IF ~3) — SEP/NMO, réhabilitation",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_toxins_mpr",
        "journal_term": f'"Toxins (Basel)"[Journal] AND spasticity[tiab] AND {_PT_FILTER}',
        "label": "Toxins (Basel) — toxine botulique spasticité, MPR (IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_neurol_phys_ther",
        "journal_term": f'"J Neurol Phys Ther"[Journal] AND {_PT_FILTER}',
        "label": "J Neurologic Physical Therapy (ANPT, IF ~4) — rééducation neurologique, gait",
        "source_type": "innovation",
        "specialty_hint": "medecine-physique",
        "min_score_hint": 6,
    },
    # ── Médecine d'urgences ───────────────────────────────────────────────────
    {
        "source": "pubmed_ann_emerg_med",
        "journal_term": f'"Ann Emerg Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals of Emergency Medicine (ACEP flagship, IF ~9) — RCTs, guidelines ACEP",
        "source_type": "recommandation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_resuscitation",
        "journal_term": f'"Resuscitation"[Journal] AND {_PT_FILTER}',
        "label": "Resuscitation (ERC/AHA, IF ~6) — arrêt cardiaque, RCP, chaines de survie",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_am_j_emerg_med",
        "journal_term": f'"Am J Emerg Med"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Emergency Medicine (Elsevier, IF ~3) — urgences générales",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_acad_emerg_med",
        "journal_term": f'"Acad Emerg Med"[Journal] AND {_PT_FILTER}',
        "label": "Academic Emergency Medicine (SAEM, IF ~4) — recherche urgences, outils décision",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_injury",
        "journal_term": f'"Injury"[Journal] AND {_PT_FILTER}',
        "label": "Injury (Elsevier, IF ~3) — traumatologie, prise en charge urgences trauma",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_emerg_med_j",
        "journal_term": f'"Emerg Med J"[Journal] AND {_PT_OR_TITLE}',
        "label": "Emergency Medicine Journal (RCEM / BMJ, IF ~4) — urgences UK/Europe",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_trauma_acute_care_surg",
        "journal_term": f'"J Trauma Acute Care Surg"[Journal] AND {_PT_FILTER}',
        "label": "J Trauma and Acute Care Surgery (EAST/WTA, IF ~3) — damage control, traumatologie",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_emerg_med",
        "journal_term": f'"J Emerg Med"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Emergency Medicine (Elsevier/AAEM, IF ~2) — urgences générales",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_scand_j_trauma_resusc",
        "journal_term": f'"Scand J Trauma Resusc Emerg Med"[Journal] AND {_PT_FILTER}',
        "label": "Scand J Trauma Resuscitation & Emergency Medicine (BioMed Central, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_j_emerg_med",
        "journal_term": f'"Eur J Emerg Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "European J Emergency Medicine (EUSEM / LWW, IF ~3) — guidelines EUSEM, Europe",
        "source_type": "recommandation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_prehosp_emerg_care",
        "journal_term": f'"Prehosp Emerg Care"[Journal] AND {_PT_OR_TITLE}',
        "label": "Prehospital Emergency Care (NAEMSP/ACEP, IF ~3) — SAMU/SMUR, pré-hospitalier",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_emerg_med_australas",
        "journal_term": f'"Emerg Med Australas"[Journal] AND {_PT_FILTER}',
        "label": "Emergency Medicine Australasia (ACEM, IF ~2) — urgences, études randomisées",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_prehosp_disaster_med",
        "journal_term": f'"Prehosp Disaster Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Prehospital and Disaster Medicine (WADEM/Cambridge, IF ~2) — médecine catastrophe",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_clin_toxicol",
        "journal_term": f'"Clin Toxicol (Phila)"[Journal] AND {_PT_OR_TITLE}',
        "label": "Clinical Toxicology (EAPCCT/AACT, IF ~3) — intoxications aiguës, antidotes",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_crit_care_urg",
        "journal_term": f'"J Crit Care"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Critical Care (Elsevier, IF ~4) — interface urgences/réanimation",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_west_j_emerg_med",
        "journal_term": f'"West J Emerg Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Western Journal of Emergency Medicine (AAEM/CAL-AAEM, IF ~2) — accès libre",
        "source_type": "innovation",
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 5,
    },
    # ── Néphrologie ───────────────────────────────────────────────────────────
    {
        "source": "pubmed_jasn",
        "journal_term": f'"J Am Soc Nephrol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of the American Society of Nephrology (ASN flagship, IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_kidney_int",
        "journal_term": f'"Kidney Int"[Journal] AND {_PT_FILTER}',
        "label": "Kidney International (ISN flagship, IF ~14) — CKD, glomérulonéphrites, transplant",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_am_j_kidney_dis",
        "journal_term": f'"Am J Kidney Dis"[Journal] AND {_PT_OR_TITLE}',
        "label": "American J Kidney Diseases (NKF / KDOQI, IF ~8) — guidelines KDOQI",
        "source_type": "recommandation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_nephrol_dial_transplant",
        "journal_term": f'"Nephrol Dial Transplant"[Journal] AND {_PT_FILTER}',
        "label": "Nephrology Dialysis Transplantation (ERA flagship, IF ~6) — dialyse, greffes, ERBP",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_cjasn",
        "journal_term": f'"Clin J Am Soc Nephrol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Clinical J American Society of Nephrology (ASN, IF ~9) — pratique clinique, KDIGO",
        "source_type": "recommandation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_nephron",
        "journal_term": f'"Nephron"[Journal] AND {_PT_FILTER}',
        "label": "Nephron (Karger, IF ~3) — pathologies rénales, études cliniques",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_nephrology_carlton",
        "journal_term": f'"Nephrology (Carlton)"[Journal] AND {_PT_FILTER}',
        "label": "Nephrology (ANZSN, IF ~2.5) — études Asie-Pacifique, dialyse, greffe",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_bmc_nephrol",
        "journal_term": f'"BMC Nephrol"[Journal] AND {_PT_FILTER}',
        "label": "BMC Nephrology (BioMed Central, IF ~3) — revues systématiques, ERC/CKD",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_perit_dial_int",
        "journal_term": f'"Perit Dial Int"[Journal] AND {_PT_OR_TITLE}',
        "label": "Peritoneal Dialysis International (ISPD, IF ~3) — dialyse péritonéale",
        "source_type": "recommandation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_hemodial_int",
        "journal_term": f'"Hemodial Int"[Journal] AND {_PT_FILTER}',
        "label": "Hemodialysis International (Wiley, IF ~2) — techniques hémodialyse, membranes",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_transplantation",
        "journal_term": f'"Transplantation"[Journal] AND {_PT_FILTER}',
        "label": "Transplantation (TTS / LWW, IF ~5) — transplantation rénale/hépatique/cardiaque",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_am_j_transplant",
        "journal_term": f'"Am J Transplant"[Journal] AND {_PT_FILTER}',
        "label": "American J Transplantation (ASTS/AST, IF ~8) — transplant rénal, immunosuppression",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_transpl_int",
        "journal_term": f'"Transpl Int"[Journal] AND {_PT_FILTER}',
        "label": "Transplant International (ESOT, IF ~4) — transplantation européenne",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_nephrol",
        "journal_term": f'"J Nephrol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Nephrology (SIN / Springer, IF ~3) — sociétés italiennes, europé.",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_clin_nephrol",
        "journal_term": f'"Clin Nephrol"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Nephrology (Dustri, IF ~2) — cas cliniques, séries, pratique",
        "source_type": "innovation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_nephrol_ther",
        "journal_term": f'"Nephrol Ther"[Journal] AND {_PT_OR_TITLE}',
        "label": "Nephrologie & Thérapeutique (SFNDT, IF ~1) — recommandations françaises néphrologie",
        "source_type": "recommandation",
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    # ── Neurochirurgie ────────────────────────────────────────────────────────
    {
        "source": "pubmed_j_neurosurg",
        "journal_term": f'"J Neurosurg"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Neurosurgery (AANS flagship, IF ~5) — neuro-oncologie, vasculaire, rachis",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_neurosurgery",
        "journal_term": f'"Neurosurgery"[Journal] AND {_PT_FILTER}',
        "label": "Neurosurgery (CNS flagship, IF ~5) — chirurgie intracrânienne, rachis, fonctionnelle",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_acta_neurochir",
        "journal_term": f'"Acta Neurochir (Wien)"[Journal] AND {_PT_FILTER}',
        "label": "Acta Neurochirurgica (EANS, IF ~3) — neurochirurgie européenne",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_world_neurosurg",
        "journal_term": f'"World Neurosurg"[Journal] AND {_PT_FILTER}',
        "label": "World Neurosurgery (WFNS / Elsevier, IF ~2) — série internationale, techniques",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_neuro_oncol",
        "journal_term": f'"Neuro Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Neuro-Oncology (SNO flagship, IF ~13) — glioblastome, méningiome, métastases",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_j_neurooncol",
        "journal_term": f'"J Neurooncol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Neuro-Oncology (SNO, IF ~4) — tumeurs cérébrales, chirurgie, RT",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_neurosurg_spine",
        "journal_term": f'"J Neurosurg Spine"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Neurosurgery: Spine (AANS, IF ~3) — chirurgie rachidienne neurochirurgicale",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_spine_j_nc",
        "journal_term": f'"Eur Spine J"[Journal] AND {_PT_FILTER}',
        "label": "European Spine Journal (EUROSPINE, IF ~3) — chirurgie rachidienne, décompression",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_spine_j_nc",
        "journal_term": f'"Spine J"[Journal] AND {_PT_FILTER}',
        "label": "Spine Journal (NASS, IF ~4) — chirurgie rachidienne, instrumentations, résultats",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_stroke",
        "journal_term": f'"Stroke"[Journal] AND {_PT_FILTER}',
        "label": "Stroke (AHA/ASA, IF ~8) — neurochirurgie vasculaire, anévrismes, HSA, MAV",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_neurocrit_care",
        "journal_term": f'"Neurocrit Care"[Journal] AND {_PT_OR_TITLE}',
        "label": "Neurocritical Care (NCS, IF ~5) — neuroréanimation, HSA, TC, HTIC",
        "source_type": "recommandation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_j_neurosurg_pediatr",
        "journal_term": f'"J Neurosurg Pediatr"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Neurosurgery: Pediatrics (AANS/CNS, IF ~2) — neurochirurgie pédiatrique",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_childs_nerv_syst",
        "journal_term": f'"Childs Nerv Syst"[Journal] AND {_PT_FILTER}',
        "label": "Child's Nervous System (ISPN, IF ~2) — neurochirurgie pédiatrique internationale",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_neurosurg_rev",
        "journal_term": f'"Neurosurg Rev"[Journal] AND {_PT_OR_TITLE}',
        "label": "Neurosurgical Review (Springer, IF ~4) — revues systématiques et méta-analyses",
        "source_type": "recommandation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_clin_neurol_neurosurg",
        "journal_term": f'"Clin Neurol Neurosurg"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Neurology and Neurosurgery (Elsevier, IF ~2) — neuro-neurochirurgie",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_stereotact_funct_neurosurg",
        "journal_term": f'"Stereotact Funct Neurosurg"[Journal] AND {_PT_FILTER}',
        "label": "Stereotactic and Functional Neurosurgery (Karger, IF ~3) — DBS, épilepsie, gamma-knife",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_oper_neurosurg",
        "journal_term": f'"Oper Neurosurg"[Journal] AND {_PT_FILTER}',
        "label": "Operative Neurosurgery (CNS open access, IF ~2) — techniques opératoires, innovations",
        "source_type": "innovation",
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 5,
    },
    # ── Neurologie ────────────────────────────────────────────────────────────
    {
        "source": "pubmed_neurology",
        "journal_term": f'"Neurology"[Journal] AND {_PT_FILTER}',
        "label": "Neurology (AAN flagship, IF ~9) — guidelines AAN, essais phase 3 neurologie",
        "source_type": "recommandation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_lancet_neurol",
        "journal_term": f'"Lancet Neurol"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Neurology (IF ~48) — essais pivots neurologie, SEP, AVC, démences",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_brain",
        "journal_term": f'"Brain"[Journal] AND {_PT_FILTER}',
        "label": "Brain (Oxford / ABN, IF ~14) — neurologie translationnelle, maladies rares",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_ann_neurol",
        "journal_term": f'"Ann Neurol"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Neurology (ANA/CNS, IF ~11) — biomarqueurs, maladies neurodégénératives",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_jnnp",
        "journal_term": f'"J Neurol Neurosurg Psychiatry"[Journal] AND {_PT_FILTER}',
        "label": "JNNP (BMJ, IF ~9) — sclérose en plaques, AVC, maladies neuromusculaires",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_eur_j_neurol",
        "journal_term": f'"Eur J Neurol"[Journal] AND {_PT_OR_TITLE}',
        "label": "European J Neurology (EAN flagship, IF ~5) — guidelines EAN, neurologie Europe",
        "source_type": "recommandation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_j_neurol",
        "journal_term": f'"J Neurol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Neurology (DGN / Springer, IF ~4) — neurologie clinique européenne",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_mov_disord",
        "journal_term": f'"Mov Disord"[Journal] AND {_PT_FILTER}',
        "label": "Movement Disorders (MDS flagship, IF ~9) — Parkinson, atrophies systémiques",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_epilepsia",
        "journal_term": f'"Epilepsia"[Journal] AND {_PT_FILTER}',
        "label": "Epilepsia (ILAE flagship, IF ~6) — épilepsie, antiépileptiques, chirurgie",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_cephalalgia",
        "journal_term": f'"Cephalalgia"[Journal] AND {_PT_FILTER}',
        "label": "Cephalalgia (IHS / SAGE, IF ~5) — migraine, céphalées, gepants, anti-CGRP",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_int_j_stroke",
        "journal_term": f'"Int J Stroke"[Journal] AND {_PT_FILTER}',
        "label": "International J Stroke (WSO, IF ~6) — AVC, thrombolyse, thrombectomie",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_cerebrovasc_dis",
        "journal_term": f'"Cerebrovasc Dis"[Journal] AND {_PT_FILTER}',
        "label": "Cerebrovascular Diseases (ESO / Karger, IF ~4) — AVC, pathologie cérébrovascul.",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_parkinsonism_relat_disord",
        "journal_term": f'"Parkinsonism Relat Disord"[Journal] AND {_PT_FILTER}',
        "label": "Parkinsonism & Related Disorders (MDS / Elsevier, IF ~4) — Parkinson, synucléopathies",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_seizure",
        "journal_term": f'"Seizure"[Journal] AND {_PT_FILTER}',
        "label": "Seizure (ILAE / Elsevier, IF ~3) — épilepsie clinique, résistance médicaments",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_neurol_sci",
        "journal_term": f'"J Neurol Sci"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Neurological Sciences (WFN / Elsevier, IF ~4) — neurologie mondiale",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_muscle_nerve",
        "journal_term": f'"Muscle Nerve"[Journal] AND {_PT_FILTER}',
        "label": "Muscle & Nerve (AANEM / Wiley, IF ~3) — maladies neuromusculaires, EMG",
        "source_type": "innovation",
        "specialty_hint": "neurologie",
        "min_score_hint": 6,
    },
    # ── Oncologie ─────────────────────────────────────────────────────────────
    {
        "source": "pubmed_j_clin_oncol",
        "journal_term": f'"J Clin Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Clinical Oncology (ASCO flagship, IF ~45) — essais pivots, guidelines ASCO",
        "source_type": "recommandation",
        "specialty_hint": "oncologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_ann_oncol",
        "journal_term": f'"Ann Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Oncology (ESMO flagship, IF ~51) — guidelines ESMO, essais phase 3",
        "source_type": "recommandation",
        "specialty_hint": "oncologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_lancet_oncol",
        "journal_term": f'"Lancet Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Oncology (IF ~42) — essais pivots tous types tumoraux",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_eur_j_cancer",
        "journal_term": f'"Eur J Cancer"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Cancer (ECCO, IF ~8) — oncologie européenne, guidelines",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_clin_cancer_res",
        "journal_term": f'"Clin Cancer Res"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Cancer Research (AACR, IF ~11) — biomarqueurs, thérapies ciblées, IO",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_br_j_cancer",
        "journal_term": f'"Br J Cancer"[Journal] AND {_PT_FILTER}',
        "label": "British Journal of Cancer (CRUK, IF ~9) — essais phase 2-3, épidémiologie",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_cancer_acs",
        "journal_term": f'"Cancer"[Journal] AND {_PT_FILTER}',
        "label": "Cancer (ACS / Wiley, IF ~7) — oncologie clinique générale, tous types tumoraux",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_jnci",
        "journal_term": f'"J Natl Cancer Inst"[Journal] AND {_PT_FILTER}',
        "label": "Journal of the National Cancer Institute (NCI, IF ~11) — études cohorte, dépistage",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_int_j_radiat_oncol",
        "journal_term": f'"Int J Radiat Oncol Biol Phys"[Journal] AND {_PT_FILTER}',
        "label": "Int J Radiation Oncology Biology Physics (ASTRO, IF ~8) — radiothérapie, SBRT, protonthérapie",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_radiother_oncol",
        "journal_term": f'"Radiother Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Radiotherapy and Oncology (ESTRO, IF ~7) — guidelines ESTRO, radiothérapie Europe",
        "source_type": "recommandation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_support_care_cancer",
        "journal_term": f'"Support Care Cancer"[Journal] AND {_PT_FILTER}',
        "label": "Supportive Care in Cancer (MASCC, IF ~4) — soins de support, fatigue, mucite",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_cancer_treat_rev",
        "journal_term": f'"Cancer Treat Rev"[Journal] AND {_PT_FILTER}',
        "label": "Cancer Treatment Reviews (Elsevier, IF ~10) — revues systématiques par type tumoral",
        "source_type": "recommandation",
        "specialty_hint": "oncologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_oncologist",
        "journal_term": f'"Oncologist"[Journal] AND {_PT_FILTER}',
        "label": "The Oncologist (ASCO / Oxford, IF ~5) — pratique clinique, cas complexes",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_esmo_open",
        "journal_term": f'"ESMO Open"[Journal] AND {_PT_FILTER}',
        "label": "ESMO Open (ESMO open access, IF ~6) — essais phase 2-3, pratique européenne",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_cancer_med",
        "journal_term": f'"Cancer Med"[Journal] AND {_PT_FILTER}',
        "label": "Cancer Medicine (Wiley open access, IF ~4) — études multicentriques, survie",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_oncotarget",
        "journal_term": f'"Oncotarget"[Journal] AND {_PT_FILTER}',
        "label": "Oncotarget (Impact Journals, IF ~4) — thérapies ciblées, biomarqueurs prédictifs",
        "source_type": "innovation",
        "specialty_hint": "oncologie",
        "min_score_hint": 5,
    },

    # ── Ophtalmologie ─────────────────────────────────────────────────────────
    {
        "source": "pubmed_ophthalmology",
        "journal_term": f'"Ophthalmology"[Journal] AND {_PT_FILTER}',
        "label": "Ophthalmology (AAO flagship, IF ~14) — essais pivots, guidelines AAO",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_jama_ophthalmol",
        "journal_term": f'"JAMA Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "JAMA Ophthalmology (JAMA Network, IF ~8) — pratique clinique, RCTs",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_br_j_ophthalmol",
        "journal_term": f'"Br J Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "British Journal of Ophthalmology (BMJ, IF ~5) — EU/UK pratique",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_am_j_ophthalmol",
        "journal_term": f'"Am J Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Ophthalmology (Elsevier, IF ~5) — clinique générale",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_retina",
        "journal_term": f'"Retina"[Journal] AND {_PT_FILTER}',
        "label": "Retina (Wolters Kluwer, IF ~5) — chirurgie vitréo-rétinienne, anti-VEGF",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_jcrs",
        "journal_term": f'"J Cataract Refract Surg"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Cataract and Refractive Surgery (ASCRS/ESCRS, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_glaucoma",
        "journal_term": f'"J Glaucoma"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Glaucoma (WGA, IF ~3) — médical et chirurgical glaucome",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_cornea",
        "journal_term": f'"Cornea"[Journal] AND {_PT_FILTER}',
        "label": "Cornea (Wolters Kluwer, IF ~3) — greffes DSAEK/DMEK, kératocône, CXL",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_graefes_arch",
        "journal_term": f'"Graefes Arch Clin Exp Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "Graefe's Archive (Springer, IF ~3) — ophtalmologie clinique EU",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_acta_ophthalmol",
        "journal_term": f'"Acta Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "Acta Ophthalmologica (EUPO/Nordic, IF ~3) — Europe du Nord",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_eye",
        "journal_term": f'"Eye (Lond)"[Journal] AND {_PT_FILTER}',
        "label": "Eye (Nature/Springer — RCOphth, IF ~3) — ophtalmologie clinique UK",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_surv_ophthalmol",
        "journal_term": f'"Surv Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "Survey of Ophthalmology (Elsevier, IF ~6) — revues systématiques",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_iovs",
        "journal_term": f'"Invest Ophthalmol Vis Sci"[Journal] AND {_PT_FILTER}',
        "label": "IOVS — Investigative Ophthalmology & Visual Science (ARVO, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_ocul_surf",
        "journal_term": f'"Ocul Surf"[Journal] AND {_PT_FILTER}',
        "label": "Ocular Surface (Elsevier, IF ~8) — sécheresse oculaire, cicatrisations",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_j_ophthalmol",
        "journal_term": f'"Eur J Ophthalmol"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Ophthalmology (SOE affiliated, IF ~2) — pratique EU",
        "source_type": "innovation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_prog_retin_eye_res",
        "journal_term": f'"Prog Retin Eye Res"[Journal] AND {_PT_FILTER}',
        "label": "Progress in Retinal and Eye Research (Elsevier, IF ~20) — revues référence",
        "source_type": "recommandation",
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 6,
    },

    # ── ORL — Oto-Rhino-Laryngologie et chirurgie cervico-faciale ─────────────
    {
        "source": "pubmed_otolaryngol_hns",
        "journal_term": f'"Otolaryngol Head Neck Surg"[Journal] AND {_PT_FILTER}',
        "label": "Otolaryngology–Head & Neck Surgery (AAO-HNS flagship, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_jama_otolaryngol",
        "journal_term": f'"JAMA Otolaryngol Head Neck Surg"[Journal] AND {_PT_FILTER}',
        "label": "JAMA Otolaryngology – Head & Neck Surgery (JAMA Network, IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_laryngoscope",
        "journal_term": f'"Laryngoscope"[Journal] AND {_PT_FILTER}',
        "label": "Laryngoscope (ALA, IF ~3) — ORL générale, chirurgie laryngée",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_head_neck",
        "journal_term": f'"Head Neck"[Journal] AND {_PT_FILTER}',
        "label": "Head & Neck (Wiley, IF ~3) — oncologie cervico-faciale",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_oral_oncol",
        "journal_term": f'"Oral Oncol"[Journal] AND {_PT_FILTER}',
        "label": "Oral Oncology (Elsevier, IF ~5) — carcinomes tête-cou, HPV, immunothérapie",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_arch_orl",
        "journal_term": f'"Eur Arch Otorhinolaryngol"[Journal] AND {_PT_FILTER}',
        "label": "European Archives of ORL (EUFOS/Springer, IF ~2) — pratique EU",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_otol_neurotol",
        "journal_term": f'"Otol Neurotol"[Journal] AND {_PT_FILTER}',
        "label": "Otology & Neurotology (AOS, IF ~2) — otologie, implants cochléaires",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_rhinology",
        "journal_term": f'"Rhinology"[Journal] AND {_PT_FILTER}',
        "label": "Rhinology (ERS — European Rhinologic Society, IF ~4) — RSC, FESS",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_clin_otolaryngol",
        "journal_term": f'"Clin Otolaryngol"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Otolaryngology (BACO/Wiley, IF ~3) — ORL clinique UK/EU",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_int_forum_allergy_rhinol",
        "journal_term": f'"Int Forum Allergy Rhinol"[Journal] AND {_PT_FILTER}',
        "label": "International Forum of Allergy & Rhinology (AAAAI/AAO, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_thyroid",
        "journal_term": f'"Thyroid"[Journal] AND {_PT_FILTER}',
        "label": "Thyroid (ATA flagship, IF ~6) — chirurgie thyroïde/parathyroïde, carcinomes",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_acta_otolaryngol",
        "journal_term": f'"Acta Otolaryngol"[Journal] AND {_PT_FILTER}',
        "label": "Acta Oto-Laryngologica (Taylor & Francis, IF ~2) — Scandinavie/EU",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_audiol_neurootol",
        "journal_term": f'"Audiol Neurootol"[Journal] AND {_PT_FILTER}',
        "label": "Audiology and Neuro-Otology (Karger, IF ~2) — audiologie clinique, vertiges",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_dysphagia",
        "journal_term": f'"Dysphagia"[Journal] AND {_PT_FILTER}',
        "label": "Dysphagia (Springer, IF ~3) — troubles déglutition, laryngologie",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_j_voice",
        "journal_term": f'"J Voice"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Voice (Elsevier, IF ~2) — phoniatrie, paralysie cordes vocales",
        "source_type": "innovation",
        "specialty_hint": "orl",
        "min_score_hint": 5,
    },
    # ── Pharmacien ────────────────────────────────────────────────────────────
    # Seuil 7 pour les flagships cliniques (Clin Pharmacol Ther IF ~7).
    # Seuil 5-6 pour pharmacie hospitalière et pharmacovigilance.
    # Note : EMA feeds (ema_news, ema_guidelines, ema_new_medicines) et has_general
    # + ansm_alertes (tous) couvrent déjà la pharmacovigilance réglementaire.
    {
        "source": "pubmed_clin_pharmacol_ther",
        "journal_term": f'"Clin Pharmacol Ther"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Pharmacology & Therapeutics (ASCPT flagship, IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_ann_pharmacother",
        "journal_term": f'"Ann Pharmacother"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Pharmacotherapy (Harvey Whitney, IF ~4) — pratique clinique",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_br_j_clin_pharmacol",
        "journal_term": f'"Br J Clin Pharmacol"[Journal] AND {_PT_FILTER}',
        "label": "British Journal of Clinical Pharmacology (BPS/Wiley, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_pharmacotherapy",
        "journal_term": f'"Pharmacotherapy"[Journal] AND {_PT_FILTER}',
        "label": "Pharmacotherapy (ACCP, IF ~3) — pharmacothérapie clinique",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_drug_safety",
        "journal_term": f'"Drug Saf"[Journal] AND {_PT_FILTER}',
        "label": "Drug Safety (Springer, IF ~4) — pharmacovigilance, EIM",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_pharmacoepidemiol_drug_saf",
        "journal_term": f'"Pharmacoepidemiol Drug Saf"[Journal] AND {_PT_FILTER}',
        "label": "Pharmacoepidemiology & Drug Safety (ISPE, IF ~3) — signaux EIM",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_am_j_health_syst_pharm",
        "journal_term": f'"Am J Health Syst Pharm"[Journal] AND {_PT_FILTER}',
        "label": "AJHP — American Journal of Health-System Pharmacy (ASHP, IF ~2)",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_eur_j_hosp_pharm",
        "journal_term": f'"Eur J Hosp Pharm"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Hospital Pharmacy (EAHP, IF ~2) — pharmaco hospitalière EU",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_int_j_clin_pharm",
        "journal_term": f'"Int J Clin Pharm"[Journal] AND {_PT_FILTER}',
        "label": "International Journal of Clinical Pharmacy (KNMP/Springer, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_drugs",
        "journal_term": f'"Drugs"[Journal] AND {_PT_FILTER}',
        "label": "Drugs (Springer, IF ~4) — revues médicaments, nouvelles molécules",
        "source_type": "recommandation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_clin_pharmacokinet",
        "journal_term": f'"Clin Pharmacokinet"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Pharmacokinetics (Springer, IF ~4) — PK/PD, suivi thérapeutique",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_biodrugs",
        "journal_term": f'"BioDrugs"[Journal] AND {_PT_FILTER}',
        "label": "BioDrugs (Springer, IF ~4) — biosimilaires, interchangeabilité, switch",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_eur_j_clin_pharmacol",
        "journal_term": f'"Eur J Clin Pharmacol"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Clinical Pharmacology (AGAH/Springer, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_ann_pharm_fr",
        "journal_term": f'"Ann Pharm Fr"[Journal] AND {_PT_FILTER}',
        "label": "Annales Pharmaceutiques Françaises (SFPC, IF ~2) ★ France — recommandations SFPC",
        "source_type": "recommandation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 4,
    },
    {
        "source": "pubmed_ther_adv_drug_saf",
        "journal_term": f'"Ther Adv Drug Saf"[Journal] AND {_PT_FILTER}',
        "label": "Therapeutic Advances in Drug Safety (SAGE, IF ~4) — sécurité pratique",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_j_clin_pharm_ther",
        "journal_term": f'"J Clin Pharm Ther"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Clinical Pharmacy and Therapeutics (Wiley, IF ~2)",
        "source_type": "innovation",
        "specialty_hint": "pharmacien",
        "min_score_hint": 5,
    },

    # ── Pneumologie ───────────────────────────────────────────────────────────
    # ERS = European Respiratory Society ; ATS = American Thoracic Society
    # Thématiques clés : BPCO/COPD, asthme sévère, ILD/FPI, HTAP, infections
    # respiratoires (PAC, PAVM), mucoviscidose, SAOS, cancer bronchique (côté
    # médical — chimiothérapie/immunothérapie, pas chirurgie).
    {
        "source": "pubmed_eur_respir_j",
        "journal_term": f'"Eur Respir J"[Journal] AND {_PT_FILTER}',
        "label": "European Respiratory Journal (ERS flagship, IF ~24)",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_ajrccm",
        "journal_term": f'"Am J Respir Crit Care Med"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Respiratory and Critical Care Medicine (ATS flagship, IF ~23)",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_lancet_respir",
        "journal_term": f'"Lancet Respir Med"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Respiratory Medicine (IF ~38) — essais pivots BPCO/asthme/ILD",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 8,
    },
    # Eur Respir Review = journal ERS dédié aux reviews cliniques et guidelines.
    # Publie les mises à jour des recommandations ERS : BPCO, FPI, HTAP, asthme,
    # apnée du sommeil. Source_type = recommandation.
    {
        "source": "pubmed_eur_respir_rev",
        "journal_term": f'"Eur Respir Rev"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Respiratory Review (ERS reviews & guidelines, IF ~10)",
        "source_type": "recommandation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 6,
    },
    # Ann Am Thorac Soc = journal ATS orienté pratique clinique, guidelines ATS
    # (COPD, spirométrie, PAC, mucoviscidose, SAOS). _PT_OR_TITLE pour guidelines.
    {
        "source": "pubmed_ann_am_thorac_soc",
        "journal_term": f'"Ann Am Thorac Soc"[Journal] AND {_PT_OR_TITLE}',
        "label": "Annals ATS — guidelines & pratique clinique (ATS, IF ~8)",
        "source_type": "recommandation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 6,
    },
    # JACI (Journal of Allergy and Clinical Immunology) — IF ~14, AAAAI/EAACI.
    # Publie les RCTs sur biothérapies asthme sévère (dupilumab, mepolizumab,
    # benralizumab, tézépélumab), rhinite allergique, allergie alimentaire.
    {
        "source": "pubmed_jaci",
        "journal_term": f'"J Allergy Clin Immunol"[Journal] AND {_PT_FILTER}',
        "label": "J Allergy Clin Immunol (AAAAI/EAACI, IF ~14) — asthme sévère, biothérapies",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 7,
    },
    # Pulmonology (SEPAR/Elsevier) — IF ~8. Journal officiel de la Sociedad
    # Española de Neumología y Cirugía Torácica. Publie des RCTs et guidelines
    # BPCO, asthme, ILD, HTAP, ventilation — bon équilibre pratique/science.
    {
        "source": "pubmed_pulmonology",
        "journal_term": f'"Pulmonology"[Journal] AND {_PT_FILTER}',
        "label": "Pulmonology (SEPAR/Elsevier, IF ~8) — BPCO, asthme, ventilation",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 6,
    },
    # Respirology (APSR — Asia Pacific Society of Respirology) — IF ~5.
    # Publie des RCTs asiatiques (BPCO, TB, cancer bronchique) et guidelines
    # APSR/ERS. Pertinent pour la diversité de populations et épidémiologie.
    {
        "source": "pubmed_respirology",
        "journal_term": f'"Respirology"[Journal] AND {_PT_FILTER}',
        "label": "Respirology (APSR, IF ~5) — BPCO, infections respiratoires",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 6,
    },
    # Respiratory Medicine (Elsevier) — IF ~4. Publie des études observationnelles
    # et RCTs de taille modeste : BPCO en soins primaires, compliance inhalateurs,
    # asthme non-sévère, diagnostics spirométriques. Volume élevé → filtre strict.
    {
        "source": "pubmed_respir_med",
        "journal_term": f'"Respir Med"[Journal] AND {_PT_FILTER}',
        "label": "Respiratory Medicine (Elsevier, IF ~4) — BPCO, inhalateurs, compliance",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 5,
    },
    # Sleep (Oxford/AASM) — IF ~7. Journal officiel AASM/ESRS. Publie les RCTs
    # CPAP/ventilation SAOS, hypnogramme, impact cardiovasculaire du SAOS,
    # nouvelles thérapies (soniprep, aremézolam). Essentiel pour le pneumologue
    # avec activité somnologie.
    {
        "source": "pubmed_sleep",
        "journal_term": f'"Sleep"[Journal] AND {_PT_FILTER}',
        "label": "Sleep (AASM/ESRS, IF ~7) — SAOS, CPAP, ventilation, somnologie",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 6,
    },
    # J Sleep Research (ESRS/Wiley) — IF ~4. Journal officiel ESRS.
    # Publie des études sur le SAOS, chronobiologie, insomnies, impact
    # cardiovasculaire. Moins exigeant que Sleep mais couverture européenne.
    {
        "source": "pubmed_j_sleep_res",
        "journal_term": f'"J Sleep Res"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Sleep Research (ESRS/Wiley, IF ~4) — SAOS, somnologie EU",
        "source_type": "innovation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 5,
    },
    # Revue des Maladies Respiratoires — journal officiel SPLF (Société de Pneumologie
    # de Langue Française). IF ~1.5. Publie les recommandations SPLF, les
    # actualisations de pratique FR, les avis d'experts en français.
    # Source prioritaire pour la réglo et les recommandations nationales FR.
    {
        "source": "pubmed_rev_mal_respir",
        "journal_term": f'"Rev Mal Respir"[Journal] AND {_PT_OR_TITLE}',
        "label": "Revue des Maladies Respiratoires (SPLF ★ France, IF ~1.5)",
        "source_type": "recommandation",
        "specialty_hint": "pneumologie",
        "min_score_hint": 4,
    },

    # ── Psychiatrie ───────────────────────────────────────────────────────────
    # Thématiques clés : épisode dépressif caractérisé (EDC), dépression résistante,
    # trouble bipolaire, schizophrénie/psychoses, troubles anxieux, TDAH adulte,
    # addictions, troubles du comportement alimentaire (TCA), psychiatrie de liaison.
    {
        "source": "pubmed_am_j_psychiatry",
        "journal_term": f'"Am J Psychiatry"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Psychiatry (APA flagship, IF ~17)",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_jama_psychiatry",
        "journal_term": f'"JAMA Psychiatry"[Journal] AND {_PT_FILTER}',
        "label": "JAMA Psychiatry (IF ~22)",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_lancet_psychiatry",
        "journal_term": f'"Lancet Psychiatry"[Journal] AND {_PT_FILTER}',
        "label": "Lancet Psychiatry (IF ~65) — essais pivots, méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 8,
    },
    # World Psychiatry — IF ~60. Journal WPA (World Psychiatric Association).
    # Publie des meta-analyses de réseau, revues systématiques et perspectives
    # cliniques de très haut niveau. _PT_OR_TITLE pour capter les reviews/guidelines.
    {
        "source": "pubmed_world_psychiatry",
        "journal_term": f'"World Psychiatry"[Journal] AND {_PT_OR_TITLE}',
        "label": "World Psychiatry (WPA, IF ~60) — méta-analyses réseau, perspectives cliniques",
        "source_type": "recommandation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_br_j_psychiatry",
        "journal_term": f'"Br J Psychiatry"[Journal] AND {_PT_FILTER}',
        "label": "British Journal of Psychiatry (Royal College, IF ~9)",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_acta_psychiatr_scand",
        "journal_term": f'"Acta Psychiatr Scand"[Journal] AND {_PT_FILTER}',
        "label": "Acta Psychiatrica Scandinavica (Nordic/Wiley, IF ~8)",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_schizophr_bull",
        "journal_term": f'"Schizophr Bull"[Journal] AND {_PT_FILTER}',
        "label": "Schizophrenia Bulletin (SRS/Oxford, IF ~8) — schizophrénie, psychoses",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_bipolar_disord",
        "journal_term": f'"Bipolar Disord"[Journal] AND {_PT_FILTER}',
        "label": "Bipolar Disorders (ISBD/Wiley, IF ~6) — trouble bipolaire, lithium",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 6,
    },
    # Neuropsychopharmacology — journal ACNP (IF ~7). Publie les RCTs sur
    # nouveaux traitements psychopharmacologiques : kétamine/eskétamine IV,
    # psilocybine, nouvelles molécules anxiolytiques et antipsychotiques.
    {
        "source": "pubmed_neuropsychopharmacol",
        "journal_term": f'"Neuropsychopharmacology"[Journal] AND {_PT_FILTER}',
        "label": "Neuropsychopharmacology (ACNP, IF ~7) — psychopharmacologie clinique",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 6,
    },
    # J Clinical Psychiatry — Physicians Postgraduate Press (IF ~5). Publie les
    # algorithmes thérapeutiques CANMAT, les guidelines de prise en charge de
    # la dépression, du TDAH adulte et des troubles anxieux. _PT_OR_TITLE.
    {
        "source": "pubmed_j_clin_psychiatry",
        "journal_term": f'"J Clin Psychiatry"[Journal] AND {_PT_OR_TITLE}',
        "label": "Journal of Clinical Psychiatry — guidelines CANMAT, algorithmes (IF ~5)",
        "source_type": "recommandation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_depress_anxiety",
        "journal_term": f'"Depress Anxiety"[Journal] AND {_PT_FILTER}',
        "label": "Depression and Anxiety (ADAA/Wiley, IF ~5) — EDC, TCA, addictions",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_int_j_neuropsychopharmacol",
        "journal_term": f'"Int J Neuropsychopharmacol"[Journal] AND {_PT_FILTER}',
        "label": "Int J Neuropsychopharmacology (CINP, IF ~5) — essais pharmacologiques EU",
        "source_type": "innovation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 5,
    },
    # L'Encéphale — journal officiel SPF (Société de Psychiatrie de France).
    # IF ~2. Publie les recommandations HAS/ANSM en psychiatrie, les actualisations
    # de pratique FR, les avis d'experts en langue française. Référence nationale.
    {
        "source": "pubmed_encephale",
        "journal_term": f'"Encephale"[Journal] AND {_PT_OR_TITLE}',
        "label": "L'Encéphale (SPF ★ France, IF ~2) — recommandations HAS, pratique FR",
        "source_type": "recommandation",
        "specialty_hint": "psychiatrie",
        "min_score_hint": 4,
    },

    # ── Radiologie (diagnostique et interventionnelle) ────────────────────────
    # Radiologie diagnostique : scanner, IRM, échographie, radiographie standard,
    # médecine nucléaire (TEP-scan, scintigraphie), IA en radiologie, reporting structuré.
    # Radiologie interventionnelle : ablation percutanée (RF/micro-ondes/cryo),
    # embolisation (HCC, fibromes, hémorragies), TACE/TARE/TIPS, ponctions-biopsies.
    {
        "source": "pubmed_radiology",
        "journal_term": f'"Radiology"[Journal] AND {_PT_FILTER}',
        "label": "Radiology (RSNA flagship, IF ~12)",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_eur_radiology",
        "journal_term": f'"Eur Radiol"[Journal] AND {_PT_FILTER}',
        "label": "European Radiology (ESR, IF ~7)",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_radiol_interv",
        "journal_term": f'"Radiology"[Journal] AND (interventional[tiab] OR ablation[tiab] OR embolization[tiab] OR embolisation[tiab] OR TACE[tiab] OR TARE[tiab] OR TIPS[tiab] OR biopsy[tiab] OR thrombectomy[tiab] OR angioplasty[tiab]) AND {_PT_FILTER}',
        "label": "Radiology — filtré interventionnel (ablation, embolisation, TACE/TARE)",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 7,
    },
    # J Vasc Interv Radiol (JVIR) — journal SIR (Society of Interventional
    # Radiology). IF ~3. Publie RCTs et guidelines sur interventions vasculaires
    # et non-vasculaires percutanées : TIPS, embolisation hépatique, ablation
    # tumorale, traitements des fibromes utérins, hémorragies post-partum.
    {
        "source": "pubmed_jvir",
        "journal_term": f'"J Vasc Interv Radiol"[Journal] AND {_PT_FILTER}',
        "label": "J Vasc Interv Radiol (SIR, IF ~3) — interventionnel vasculaire et percutané",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 6,
    },
    # CardioVascular Interventional Radiology (CVIR) — journal officiel CIRSE
    # (Cardiovascular and Interventional Radiological Society of Europe). IF ~3.
    # Publie les guidelines CIRSE (ablation, embolisation), essais EU d'RI.
    {
        "source": "pubmed_cvir",
        "journal_term": f'"Cardiovasc Intervent Radiol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Cardiovascular Interventional Radiology (CIRSE, IF ~3) — guidelines EU RI",
        "source_type": "recommandation",
        "specialty_hint": "radiologie",
        "min_score_hint": 5,
    },
    # AJNR (American Journal of Neuroradiology) — journal ASNR (IF ~3).
    # Publie les études sur IRM cérébrale, neuroradiologie interventionnelle
    # (thrombectomie mécanique — overlap avec neurochirurgie), imagerie rachidienne.
    {
        "source": "pubmed_ajnr",
        "journal_term": f'"AJNR Am J Neuroradiol"[Journal] AND {_PT_FILTER}',
        "label": "AJNR — American Journal of Neuroradiology (ASNR, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_ajr",
        "journal_term": f'"AJR Am J Roentgenol"[Journal] AND {_PT_FILTER}',
        "label": "American Journal of Roentgenology (ARRS, IF ~4) — pratique diagnostique",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 6,
    },
    # RadioGraphics (RSNA) — IF ~4. Journal d'enseignement et de mise à jour.
    # Publie des articles de formation continue structurés : protocoles IRM,
    # sémiologie TDM, pictorial reviews. Source_type = recommandation.
    # _PT_OR_TITLE pour capter les reviews d'enseignement.
    {
        "source": "pubmed_radiographics",
        "journal_term": f'"Radiographics"[Journal] AND {_PT_OR_TITLE}',
        "label": "RadioGraphics (RSNA — formation continue & protocoles, IF ~4)",
        "source_type": "recommandation",
        "specialty_hint": "radiologie",
        "min_score_hint": 5,
    },
    # Eur J Nucl Med Mol Imaging — journal EANM (European Association of Nuclear
    # Medicine). IF ~9. Publie les guidelines EANM (TEP-FDG oncologie, PSMA,
    # cardiologie nucléaire, neurologie), nouvelles radiotraceurs (FAPI, amyloïde),
    # théranostique (lutetium-177, actinium-225).
    {
        "source": "pubmed_ejnmmi",
        "journal_term": f'"Eur J Nucl Med Mol Imaging"[Journal] AND {_PT_FILTER}',
        "label": "Eur J Nucl Med Mol Imaging (EANM, IF ~9) — TEP, théranostique, guidelines",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 7,
    },
    # Journal of Nuclear Medicine — journal SNM/MIRD (IF ~9). Référence américaine
    # pour la médecine nucléaire : TEP-FDG, TEP-PSMA prostate, dosimétrie,
    # radiopharmaceutiques thérapeutiques (lutetium-177-DOTATATE, PRRT).
    {
        "source": "pubmed_j_nucl_med",
        "journal_term": f'"J Nucl Med"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Nuclear Medicine (SNMMI, IF ~9) — TEP, radiothérapie interne",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 7,
    },
    # Insights into Imaging — journal open-access ESR (IF ~4). Publie les
    # consensus ESR, les whitepapers sur IA en radiologie, les guidelines
    # ESR/EuroSafe Imaging (radioprotection). _PT_OR_TITLE pour guidelines.
    {
        "source": "pubmed_insights_imaging",
        "journal_term": f'"Insights Imaging"[Journal] AND {_PT_OR_TITLE}',
        "label": "Insights into Imaging (ESR OA, IF ~4) — consensus ESR, IA, radioprotection",
        "source_type": "recommandation",
        "specialty_hint": "radiologie",
        "min_score_hint": 5,
    },
    # European Journal of Radiology — Elsevier (IF ~3). Volume élevé mais publie
    # des études cliniques en radiologie diagnostique : protocoles, comparaisons
    # de techniques (IRM vs TDM), études de performance diagnostique.
    {
        "source": "pubmed_eur_j_radiol",
        "journal_term": f'"Eur J Radiol"[Journal] AND {_PT_FILTER}',
        "label": "European Journal of Radiology (Elsevier, IF ~3)",
        "source_type": "innovation",
        "specialty_hint": "radiologie",
        "min_score_hint": 5,
    },

    # ── Rhumatologie ──────────────────────────────────────────────────────────
    # Thématiques clés : rhumatismes inflammatoires (PR, SpA, rhumatisme psoriasique),
    # connectivites (LES, Sjögren, SSc, myopathies), microcrystallines (goutte, CPPD),
    # arthrose, ostéoporose, vascularites (ANCA, ACG/PPR).
    {
        "source": "pubmed_ard",
        "journal_term": f'"Ann Rheum Dis"[Journal] AND {_PT_FILTER}',
        "label": "Annals of the Rheumatic Diseases (EULAR/BMJ flagship, IF ~27)",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_arthritis_rheumatol",
        "journal_term": f'"Arthritis Rheumatol"[Journal] AND {_PT_FILTER}',
        "label": "Arthritis & Rheumatology (ACR flagship, IF ~14)",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_rheumatology_oxford",
        "journal_term": f'"Rheumatology (Oxford)"[Journal] AND {_PT_FILTER}',
        "label": "Rheumatology Oxford (BSR, IF ~6) — guidelines BSR, pratique EU",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 7,
    },
    # Journal of Autoimmunity — IF ~12. Publie des études sur connectivites
    # (LES, SSc, Sjögren, myopathies inflammatoires), biomarqueurs d'auto-immunité,
    # physiopathologie immunologique avec résultats cliniques. Pertinent pour
    # la rhumatologie des maladies systémiques.
    {
        "source": "pubmed_j_autoimmun",
        "journal_term": f'"J Autoimmun"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Autoimmunity (IF ~12) — connectivites, LES, SSc, myopathies",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 7,
    },
    # Osteoarthritis & Cartilage — journal officiel OARSI (IF ~8). THE référence
    # pour l'arthrose : essais sur AINS, traitements intra-articulaires
    # (PRP, acide hyaluronique, corticoïdes), biothérapies arthrose (anti-NGF),
    # imagerie IRM arthrose, chirurgie vs conservateur.
    {
        "source": "pubmed_osteoarthritis_cartilage",
        "journal_term": f'"Osteoarthritis Cartilage"[Journal] AND {_PT_FILTER}',
        "label": "Osteoarthritis & Cartilage (OARSI, IF ~8) — arthrose, traitements intra-articulaires",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_arthritis_res_ther",
        "journal_term": f'"Arthritis Res Ther"[Journal] AND {_PT_FILTER}',
        "label": "Arthritis Research & Therapy (BMC/BioMed, IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_j_rheumatol",
        "journal_term": f'"J Rheumatol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Rheumatology (JRheum, IF ~4) — pratique clinique, guidelines CRA",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 6,
    },
    # RMD Open — journal open-access officiel EULAR (IF ~5). Publie les
    # recommandations EULAR secondaires, les consensus points-to-consider et
    # les études complémentaires aux ARD. _PT_OR_TITLE pour les recommandations.
    {
        "source": "pubmed_rmd_open",
        "journal_term": f'"RMD Open"[Journal] AND {_PT_OR_TITLE}',
        "label": "RMD Open (EULAR OA, IF ~5) — recommandations EULAR, consensus",
        "source_type": "recommandation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_semin_arthritis_rheum",
        "journal_term": f'"Semin Arthritis Rheum"[Journal] AND {_PT_OR_TITLE}',
        "label": "Seminars in Arthritis & Rheumatism (IF ~5) — revues systématiques, méta-analyses",
        "source_type": "recommandation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_lupus",
        "journal_term": f'"Lupus"[Journal] AND {_PT_FILTER}',
        "label": "Lupus (SAGE, IF ~4) — LES, SAPL, néphrite lupique",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_clin_rheumatol",
        "journal_term": f'"Clin Rheumatol"[Journal] AND {_PT_FILTER}',
        "label": "Clinical Rheumatology (ILAR, IF ~4) — études pratiques, vie réelle",
        "source_type": "innovation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 5,
    },
    # Revue du Rhumatisme — journal officiel SFR (Société Française de Rhumatologie).
    # IF ~2. Publie les recommandations SFR, les actualisations de pratique FR,
    # les mises au point en langue française. Référence nationale.
    {
        "source": "pubmed_rev_rhum",
        "journal_term": f'"Rev Rhum Engl Ed"[Journal] AND {_PT_OR_TITLE}',
        "label": "Revue du Rhumatisme (SFR ★ France, IF ~2) — recommandations SFR",
        "source_type": "recommandation",
        "specialty_hint": "rhumatologie",
        "min_score_hint": 4,
    },

    # ── Sage-femme ────────────────────────────────────────────────────────────
    # Journaux dédiés maïeutique / périnatalité — distincts des journaux obstétricaux
    # généralistes déjà mappés sur gynécologie (BJOG/AJOG/AOGS).
    # Thématiques clés : suivi grossesse normale, accouchement physiologique,
    # HPP, allaitement, dépression périnatale, prééclampsie, diabète gestationnel,
    # contraception, dépistage col/HPV, compétences réglementaires sage-femme FR.
    {
        "source": "pubmed_midwifery",
        "journal_term": f'"Midwifery"[Journal] AND {_PT_FILTER}',
        "label": "Midwifery (RCM/Elsevier, IF ~3) — pratique maïeutique, accouchement",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_birth",
        "journal_term": f'"Birth"[Journal] AND {_PT_FILTER}',
        "label": "Birth (Wiley/ICEA, IF ~3) — travail, analgésie, physiologie",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_women_birth",
        "journal_term": f'"Women Birth"[Journal] AND {_PT_FILTER}',
        "label": "Women and Birth (ACMI/Elsevier, IF ~3) — maïeutique, expérience patient",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    # J Midwifery & Women's Health — journal officiel ACNM (American College of
    # Nurse-Midwives). IF ~2. Publie les guidelines ACNM, les protocoles de
    # pratique maïeutique et les mises à jour de compétences. _PT_OR_TITLE.
    {
        "source": "pubmed_j_midwifery",
        "journal_term": f'"J Midwifery Womens Health"[Journal] AND {_PT_OR_TITLE}',
        "label": "J Midwifery & Women's Health (ACNM, IF ~2) — guidelines maïeutique",
        "source_type": "recommandation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 4,
    },
    # Prenatal Diagnosis — Wiley (IF ~3). Publie les études sur le dépistage
    # prénatal (cfADN, marqueurs sériques T1/T2, échographie morphologique),
    # diagnostic invasif (amniocentèse, biopsie trophoblaste), T21, anomalies
    # chromosomiques. Pertinent pour la sage-femme échographiste.
    {
        "source": "pubmed_prenat_diagn",
        "journal_term": f'"Prenat Diagn"[Journal] AND {_PT_FILTER}',
        "label": "Prenatal Diagnosis (Wiley, IF ~3) — cfADN, dépistage T21, échographie",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 6,
    },
    # J Matern Fetal Neonatal Med — Taylor & Francis (IF ~3). Publie des études
    # sur les grossesses pathologiques (prééclampsie, MAP, RCIU, diabète
    # gestationnel) et le nouveau-né à terme. Bon équilibre périnatalité.
    {
        "source": "pubmed_j_matern_fetal",
        "journal_term": f'"J Matern Fetal Neonatal Med"[Journal] AND {_PT_FILTER}',
        "label": "J Matern Fetal Neonatal Med (T&F, IF ~3) — grossesses pathologiques, périnatalité",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    # Breastfeeding Medicine — journal officiel ABM (Academy of Breastfeeding
    # Medicine). IF ~3. Publie les Protocoles ABM (références mondiales
    # allaitement), les RCTs sur supplémentation galactogènes, substituts,
    # lactation induite, sevrage, et les recommandations OMS.
    {
        "source": "pubmed_breastfeed_med",
        "journal_term": f'"Breastfeed Med"[Journal] AND {_PT_OR_TITLE}',
        "label": "Breastfeeding Medicine (ABM, IF ~3) — protocoles allaitement, lactation",
        "source_type": "recommandation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    # Journal of Human Lactation — journal officiel ILCA (International Lactation
    # Consultant Association). IF ~3. Publie des essais sur les pratiques
    # d'allaitement en maternité, IBCLC, sevrage, alimentation mixte.
    {
        "source": "pubmed_j_hum_lact",
        "journal_term": f'"J Hum Lact"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Human Lactation (ILCA, IF ~3) — allaitement, consultation lactation",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    # Archives of Women's Mental Health — Springer (IF ~4). Publie des études
    # sur la dépression périnatale (EPDS), l'anxiété gestationnelle, le PTSD
    # obstétrical, les psychoses du post-partum. Essentiel pour le dépistage
    # par la sage-femme en suivi post-natal.
    {
        "source": "pubmed_arch_womens_ment_health",
        "journal_term": f'"Arch Womens Ment Health"[Journal] AND {_PT_FILTER}',
        "label": "Archives of Women's Mental Health (Springer, IF ~4) — dépression périnatale, EPDS",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 6,
    },
    # Maternal & Child Nutrition — Wiley (IF ~4). Publie des essais sur la
    # nutrition pendant la grossesse (folates, fer, iode, vitamine D, DHA),
    # l'allaitement exclusif (recommandations OMS/ESPGHAN), les pratiques de
    # diversification et la nutrition du nourrisson.
    {
        "source": "pubmed_matern_child_nutr",
        "journal_term": f'"Matern Child Nutr"[Journal] AND {_PT_FILTER}',
        "label": "Maternal & Child Nutrition (Wiley, IF ~4) — nutrition grossesse, allaitement, nourrisson",
        "source_type": "innovation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 5,
    },
    # International Breastfeeding Journal — BioMed Central (open-access, IF ~3).
    # Publie des études de pratiques d'allaitement, adhésion aux recommandations
    # OMS/HAS, interventions de soutien. Source complémentaire à Breastfeed Med.
    {
        "source": "pubmed_int_breastfeed_j",
        "journal_term": f'"Int Breastfeed J"[Journal] AND {_PT_OR_TITLE}',
        "label": "International Breastfeeding Journal (BMC OA, IF ~3)",
        "source_type": "recommandation",
        "specialty_hint": "sage-femme",
        "min_score_hint": 4,
    },

    # ── Urologie ──────────────────────────────────────────────────────────────
    # Thématiques clés : cancer de la prostate (localisé, CSPC, CRPC),
    # cancer de la vessie (TVNIM/TVIM, urothélial métastatique),
    # cancer du rein, lithiase, HBP/LUTS, incontinence, transplantation rénale.
    {
        "source": "pubmed_eur_urol",
        "journal_term": f'"Eur Urol"[Journal] AND {_PT_FILTER}',
        "label": "European Urology (EAU flagship, IF ~25)",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 8,
    },
    {
        "source": "pubmed_eur_urol_oncol",
        "journal_term": f'"Eur Urol Oncol"[Journal] AND {_PT_FILTER}',
        "label": "European Urology Oncology (EAU, IF ~8) — oncologie urologique",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 7,
    },
    {
        "source": "pubmed_j_urol",
        "journal_term": f'"J Urol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Urology (AUA flagship, IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 7,
    },
    # Prostate Cancer & Prostatic Diseases — Nature Portfolio (IF ~6).
    # Publie RCTs et méta-analyses sur cancer de la prostate (biopsie, traitement
    # localisé, castration, résistance), biomarqueurs (PSA, PHI, IsoPSA).
    {
        "source": "pubmed_prostate_cancer",
        "journal_term": f'"Prostate Cancer Prostatic Dis"[Journal] AND {_PT_FILTER}',
        "label": "Prostate Cancer & Prostatic Diseases (Nature, IF ~6)",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 6,
    },
    {
        "source": "pubmed_bjui",
        "journal_term": f'"BJU Int"[Journal] AND {_PT_FILTER}',
        "label": "BJUI — British Journal of Urology International (BAUS, IF ~5)",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 6,
    },
    # European Urology Focus — journal open-access EAU (IF ~4). Publie les
    # résumés de guidelines EAU, les commentaires d'experts sur les mises à jour
    # et les vidéos techniques. _PT_OR_TITLE pour guidelines.
    {
        "source": "pubmed_eur_urol_focus",
        "journal_term": f'"Eur Urol Focus"[Journal] AND {_PT_OR_TITLE}',
        "label": "European Urology Focus (EAU OA, IF ~4) — guidelines EAU, commentaires",
        "source_type": "recommandation",
        "specialty_hint": "urologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_world_j_urol",
        "journal_term": f'"World J Urol"[Journal] AND {_PT_FILTER}',
        "label": "World Journal of Urology (Springer, IF ~4)",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 5,
    },
    # Journal of Endourology — Mary Ann Liebert (IF ~3). Publie les RCTs sur
    # techniques endourologiques : urétéroscopie souple (URS), NLPC, lithotritie,
    # laser (Holmium, Thulium), chirurgie robotique mini-invasive.
    {
        "source": "pubmed_j_endourol",
        "journal_term": f'"J Endourol"[Journal] AND {_PT_FILTER}',
        "label": "Journal of Endourology (MAL, IF ~3) — URS, NLPC, laser, robotique",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 5,
    },
    # Neurourology & Urodynamics — journal officiel ICS (International Continence
    # Society). IF ~3. Publie des études sur l'incontinence urinaire, l'urodynamique,
    # le TVT/TOT, le sphincter artificiel, la neuromodulation sacrée (SNM).
    {
        "source": "pubmed_neurourol_urodyn",
        "journal_term": f'"Neurourol Urodyn"[Journal] AND {_PT_FILTER}',
        "label": "Neurourology & Urodynamics (ICS, IF ~3) — incontinence, urodynamique, SNM",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_urology",
        "journal_term": f'"Urology"[Journal] AND {_PT_FILTER}',
        "label": "Urology (Elsevier, IF ~3) — pratique clinique générale",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 5,
    },
    {
        "source": "pubmed_int_j_urol",
        "journal_term": f'"Int J Urol"[Journal] AND {_PT_FILTER}',
        "label": "International Journal of Urology (JUA, IF ~3) — données Asie-Pacifique",
        "source_type": "innovation",
        "specialty_hint": "urologie",
        "min_score_hint": 5,
    },
    # Progrès en Urologie — journal officiel AFU (Association Française d'Urologie).
    # IF ~1. Publie les recommandations AFU, les mises à jour de pratique française,
    # les avis d'experts en langue française. Référence nationale incontournable.
    {
        "source": "pubmed_prog_urol",
        "journal_term": f'"Prog Urol"[Journal] AND {_PT_OR_TITLE}',
        "label": "Progrès en Urologie (AFU ★ France, IF ~1) — recommandations AFU",
        "source_type": "recommandation",
        "specialty_hint": "urologie",
        "min_score_hint": 4,
    },

    # ── ORL — guidelines / recommandations ───────────────────────────────────
    # EPOS = European Position Paper on Rhinosinusitis and Nasal Polyps
    # Publié dans Rhinology (journal ERS) — filtre sur recommandations EPOS/ERS.
    {
        "source": "pubmed_epos_guidelines",
        "journal_term": (
            '"Rhinology"[Journal] AND ('
            'guideline[Title] OR "EPOS"[tiab] OR '
            '"European Position Paper"[tiab] OR '
            '"consensus statement"[Title] OR "position statement"[Title] OR '
            '"expert consensus"[Title]'
            ')'
        ),
        "label": "EPOS Guidelines — Rhinology / European Rhinologic Society",
        "source_type": "recommandation",
        "specialty_hint": "orl",
        "min_score_hint": 4,
    },
]


# ---------------------------------------------------------------------------
# Helpers NCBI E-utilities
# ---------------------------------------------------------------------------

def _ncbi_params(extra: dict) -> dict:
    """Paramètres de base pour toutes les requêtes NCBI."""
    p: dict = {"db": "pubmed", "retmode": "json", "tool": "med-news-back", "email": "contact@mednews.fr"}
    if NCBI_API_KEY:
        p["api_key"] = NCBI_API_KEY
    p.update(extra)
    return p


def _search_pmids(journal_term: str, days: int, client: httpx.Client) -> list[str]:
    """
    Recherche les PMIDs publiés dans [today-days, today] pour un journal donné.
    retmax adapté à la fenêtre : 200 pour ≤35 jours, 500 pour le run initial (>35 j).
    """
    since = (date.today() - timedelta(days=days)).strftime("%Y/%m/%d")
    today = date.today().strftime("%Y/%m/%d")
    term = f'{journal_term} AND ("{since}"[PDAT] : "{today}"[PDAT])'
    retmax = 500 if days > 35 else 200
    params = _ncbi_params({
        "term": term,
        "retmax": retmax,
        "sort": "date",
    })
    try:
        r = client.get(f"{NCBI_BASE}/esearch.fcgi", params=params, timeout=15)
        r.raise_for_status()
        data = r.json()
        return data.get("esearchresult", {}).get("idlist", [])
    except Exception as e:
        logger.warning("[pubmed] esearch error for %s: %s", journal_term, e)
        return []


def _fetch_articles(pmids: list[str], client: httpx.Client) -> list[dict]:
    """
    Récupère les détails (titre, abstract, date, DOI) pour une liste de PMIDs.
    Traitement par lots de 20 pour respecter les limites NCBI.
    """
    articles = []
    batch_size = 20
    for i in range(0, len(pmids), batch_size):
        batch = pmids[i : i + batch_size]
        params = _ncbi_params({
            "id": ",".join(batch),
            "rettype": "abstract",
            "retmode": "xml",
        })
        try:
            r = client.get(f"{NCBI_BASE}/efetch.fcgi", params=params, timeout=20)
            r.raise_for_status()
            articles.extend(_parse_efetch_xml(r.text))
        except Exception as e:
            logger.warning("[pubmed] efetch error for batch %s: %s", batch[:3], e)
        # Rate limit : 3 req/s sans clé, 10 req/s avec clé
        time.sleep(0.35 if NCBI_API_KEY else 0.4)
    return articles


def _parse_efetch_xml(xml_text: str) -> list[dict]:
    """Parse le XML efetch → liste de dicts avec les champs utiles."""
    results = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.warning("[pubmed] XML parse error: %s", e)
        return []

    for article in root.findall(".//PubmedArticle"):
        try:
            medline = article.find("MedlineCitation")
            if medline is None:
                continue

            pmid_el = medline.find("PMID")
            pmid = pmid_el.text.strip() if pmid_el is not None else None
            if not pmid:
                continue

            art = medline.find("Article")
            if art is None:
                continue

            # Titre
            title_el = art.find("ArticleTitle")
            title = "".join(title_el.itertext()).strip() if title_el is not None else ""

            # Abstract
            abstract_parts = []
            for ab in art.findall(".//AbstractText"):
                label = ab.get("Label")
                text = "".join(ab.itertext()).strip()
                if text:
                    abstract_parts.append(f"{label}: {text}" if label else text)
            abstract = "\n".join(abstract_parts)

            # Date de publication
            pub_date = _extract_pub_date(art, medline)

            # DOI
            doi = None
            for id_el in article.findall(".//ArticleId"):
                if id_el.get("IdType") == "doi":
                    doi = id_el.text.strip() if id_el.text else None
                    break

            # Journal
            journal_el = art.find("Journal/Title")
            journal = journal_el.text.strip() if journal_el is not None else ""

            results.append({
                "pmid": pmid,
                "title": title,
                "abstract": abstract,
                "pub_date": pub_date,
                "doi": doi,
                "journal": journal,
            })
        except Exception as e:
            logger.debug("[pubmed] article parse error: %s", e)
            continue

    return results


def _extract_pub_date(art_el: ET.Element, medline_el: ET.Element) -> date:
    """Extrait la date de publication de l'article (ArticleDate > PubDate > today)."""
    # ArticleDate (electronic pub date — la plus précise)
    for ad in art_el.findall("ArticleDate"):
        try:
            y = int(ad.findtext("Year", "0"))
            m = int(ad.findtext("Month", "1"))
            d = int(ad.findtext("Day", "1"))
            if y > 2000:
                return date(y, m, d)
        except (ValueError, TypeError):
            pass

    # PubDate (dans Journal/JournalIssue)
    for pd in art_el.findall(".//PubDate"):
        try:
            y = int(pd.findtext("Year", "0"))
            m_raw = pd.findtext("Month", "1")
            m = _month_str_to_int(m_raw)
            d = int(pd.findtext("Day", "1"))
            if y > 2000:
                return date(y, m, d)
        except (ValueError, TypeError):
            pass

    # MedlineDate fallback (ex: "2026 Jan-Feb")
    ml_date = art_el.findtext(".//MedlineDate", "")
    if ml_date:
        parts = ml_date.split()
        try:
            y = int(parts[0])
            m = _month_str_to_int(parts[1][:3]) if len(parts) > 1 else 1
            return date(y, m, 1)
        except (ValueError, IndexError):
            pass

    return date.today()


_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

def _month_str_to_int(s: str) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return _MONTH_MAP.get((s or "").lower()[:3], 1)


# ---------------------------------------------------------------------------
# Collecteur principal
# ---------------------------------------------------------------------------

def collect_pubmed_source(source_cfg: dict, days: int = 120) -> dict[str, int]:
    """
    Collecte les articles PubMed pour une source donnée et les insère en base.

    Returns:
        {"fetched": N, "inserted": N, "skipped": N, "errors": N}
    """
    src = source_cfg["source"]
    journal_term = source_cfg["journal_term"]
    specialty_hint = source_cfg.get("specialty_hint", "")
    source_type = source_cfg.get("source_type", "innovation")

    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}

    with httpx.Client(follow_redirects=True) as client:
        pmids = _search_pmids(journal_term, days=days, client=client)
        if not pmids:
            logger.info("[pubmed/%s] no PMIDs found for last %d days", src, days)
            return stats

        stats["fetched"] = len(pmids)
        logger.info("[pubmed/%s] %d PMIDs found", src, len(pmids))

        articles = _fetch_articles(pmids, client=client)

    with get_conn() as conn:
        with conn.cursor() as cur:
            for art in articles:
                try:
                    pmid = art["pmid"]
                    pub_date = art["pub_date"]
                    title = art["title"] or "(sans titre)"
                    abstract = art.get("abstract") or ""
                    doi = art.get("doi")
                    official_url = f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/"

                    raw_payload = {
                        "pmid": pmid,
                        "title": title,
                        "abstract": abstract,
                        "journal": art.get("journal", ""),
                        "pub_date": str(pub_date),
                        "doi": doi,
                        "source": src,
                        "source_type": source_type,
                        "specialty_hint": specialty_hint,
                    }

                    row = build_candidate_row(
                        source=src,
                        external_id=pmid,
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=abstract if abstract else None,
                        raw_payload=raw_payload,
                    )

                    inserted = insert_candidate(cur, row)
                    if inserted:
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1

                except Exception as e:
                    logger.warning("[pubmed/%s] insert error for pmid %s: %s", src, art.get("pmid"), e)
                    stats["errors"] += 1

        conn.commit()

    logger.info("[pubmed/%s] done — %s", src, stats)
    return stats


def collect_all_pubmed(days: int = 120) -> dict[str, dict]:
    """Collecte toutes les sources PubMed configurées."""
    results = {}
    for source_cfg in PUBMED_SOURCES:
        src = source_cfg["source"]
        try:
            results[src] = collect_pubmed_source(source_cfg, days=days)
        except Exception as e:
            logger.error("[pubmed/%s] erreur: %s", src, e)
            results[src] = {"error": str(e)}
    return results


# ---------------------------------------------------------------------------
# Enrichissement — re-fetch des abstracts manquants
# ---------------------------------------------------------------------------

def enrich_empty_abstracts() -> dict[str, int]:
    """
    Re-fetche les abstracts PubMed pour les candidats sans content_raw.

    Cas ciblé : articles collectés (pubmed_*) où l'abstract était absent
    lors du premier passage — souvent dû à un rate-limit NCBI ou un timeout.
    Les articles sans abstract sur PubMed (lettres, errata) restent vides :
    c'est voulu, le LLM travaillera sur le titre seul.

    Returns:
        {"checked": N, "enriched": N, "still_empty": N, "errors": N}
    """
    stats: dict[str, int] = {"checked": 0, "enriched": 0, "still_empty": 0, "errors": 0}

    # 1. Candidats PubMed sans abstract, pas encore traités par le LLM
    #    Le PMID est stocké dans raw_json->>'pmid' (colonne JSONB)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, raw_json->>'pmid' AS pmid
                FROM candidates
                WHERE source LIKE 'pubmed\\_%%'
                  AND (content_raw IS NULL OR TRIM(content_raw) = '')
                  AND status NOT IN ('LLM_DONE', 'APPROVED', 'REJECTED')
                  AND raw_json->>'pmid' IS NOT NULL
            """)
            rows = cur.fetchall()

    if not rows:
        logger.info("[pubmed/enrich] aucun candidat sans abstract")
        return stats

    stats["checked"] = len(rows)
    pmid_to_db_id: dict[str, Any] = {row[1]: row[0] for row in rows}
    pmids = list(pmid_to_db_id.keys())

    logger.info("[pubmed/enrich] %d candidats sans abstract à enrichir", len(pmids))

    # 2. Récupération des abstracts via NCBI efetch
    with httpx.Client(follow_redirects=True) as client:
        articles = _fetch_articles(pmids, client=client)

    # 3. Mise à jour en base
    with get_conn() as conn:
        with conn.cursor() as cur:
            for art in articles:
                pmid = art.get("pmid")
                abstract = art.get("abstract") or ""
                db_id = pmid_to_db_id.get(pmid)
                if not db_id:
                    continue
                if not abstract.strip():
                    stats["still_empty"] += 1
                    continue
                try:
                    cur.execute(
                        """
                        UPDATE candidates
                        SET content_raw = %s
                        WHERE id = %s
                          AND (content_raw IS NULL OR TRIM(content_raw) = '')
                        """,
                        (abstract, db_id),
                    )
                    if cur.rowcount > 0:
                        stats["enriched"] += 1
                    else:
                        stats["still_empty"] += 1
                except Exception as e:
                    logger.warning("[pubmed/enrich] update error pmid=%s: %s", pmid, e)
                    stats["errors"] += 1
        conn.commit()

    logger.info("[pubmed/enrich] done — %s", stats)
    return stats
