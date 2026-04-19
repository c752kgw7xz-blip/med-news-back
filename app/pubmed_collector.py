# app/pubmed_collector.py
"""
Collecteur PubMed via NCBI E-utilities.

Utilisé pour les journaux dont le RSS éditeur est mort (Elsevier 410 Gone,
JAMA Surgery 403 depuis avril 2026), notamment en chirurgie vasculaire et cardiaque.

API : https://eutils.ncbi.nlm.nih.gov/entrez/eutils/
  - esearch.fcgi : recherche par journal + filtre thématique + date → liste PMIDs
  - efetch.fcgi  : récupération détails XML par lot de PMIDs (titres, abstracts, dates)

Rate limit NCBI :
  - Sans clé  : 3 req/s
  - Avec clé  : 10 req/s (NCBI_API_KEY dans l'env)
  Stratégie : batch de 20 PMIDs par efetch + sleep entre lots si nécessaire.

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
        "specialty_hint": "chirurgie-cardiaque",
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
        "journal_term": f'"Ann Thorac Surg"[Journal] AND {_PT_FILTER}',
        "label": "Annals of Thoracic Surgery — RCTs & méta-analyses",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-cardiaque",
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
    Retourne au max 200 PMIDs (suffisant pour un run mensuel).
    """
    since = (date.today() - timedelta(days=days)).strftime("%Y/%m/%d")
    today = date.today().strftime("%Y/%m/%d")
    term = f'{journal_term} AND ("{since}"[PDAT] : "{today}"[PDAT])'
    params = _ncbi_params({
        "term": term,
        "retmax": 200,
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
        # Supprimer retmode=json (déjà en xml)
        params["retmode"] = "xml"
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

def collect_pubmed_source(source_cfg: dict, days: int = 90) -> dict[str, int]:
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


def collect_all_pubmed(days: int = 90) -> dict[str, dict]:
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
