# app/sources.py
"""
Toutes les sources RSS du pipeline MedNews — point de vérité unique.

Organisées par NATURE DE SOURCE (qui publie), pas par contenu.
Le contenu de chaque article est routé par le LLM via source_type + specialty_hint.

Sections :
  1. RÉGULATION FRANÇAISE     [FR_REGULATORY_FEEDS]   — HAS, ANSM, BO, SPF, CNOM, Académie
  2. SOCIÉTÉS SAVANTES FR     [FR_SOCIETIES_FEEDS]    — SFAR, SNFGE, AFU, SFN, SFMU…
  3. AGENCES & SOCIÉTÉS EU    [EU_FEEDS]              — EMA, ECDC, ESC, ESMO, EULAR, ERS…
  4. JOURNAUX ACADÉMIQUES     [JOURNALS_FEEDS]        — JAMA, NEJM, Lancet, BMJ, Blood, JCO…
  5. PRESSE CLINIQUE          [CLINICAL_PRESS_FEEDS]  — Healio, TCTMD, MedPage, ENTtoday…

Point d'entrée unique  : ALL_FEEDS — utilisé dans rss_collector.py
Scraping HTML (non-RSS): EU_WEB_SOURCES — utilisé dans web_scraper.py

Champs communs sur chaque feed :
  url          : URL du flux RSS
  label        : libellé lisible
  source       : slug unique (clé dans SOURCE_TO_TYPE + SOURCE_SPECIALTY_HINTS)
  source_type  : "reglementaire" | "recommandation" | "innovation" — indicatif uniquement.
                 Pour les sources institutionnelles (JORF, ANSM…) : déterministe via SOURCE_TO_TYPE.
                 Pour les journaux et sociétés savantes : déterminé par le LLM depuis le contenu.
  audience     : ["medecins"] | ["pharmaciens"] | ["medecins", "pharmaciens"] | …
  specialty_hint: slug spécialité (optionnel — absent = LLM route librement)
  min_score_hint: seuil LLM min (optionnel — absent = défaut 5)
"""

from __future__ import annotations


# =============================================================================
# SECTION 1 — RÉGULATION FRANÇAISE
# HAS (RBP, CT, DM), ANSM (alertes, ruptures), BO Social, SPF,
# CNOM, Académie Nationale de Médecine
# =============================================================================

FR_REGULATORY_FEEDS: list[dict] = [

    # ── HAS — Recommandations de bonne pratique (flux principal) ─────────
    # Inclus : RBP, recommandations vaccinales, guides parcours, outils
    # Enrichissement : scraping de la page HTML via has_scraper.py
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081452",
        "label": "HAS — Recommandations et guides (RBP)",
        "source": "has_rbp",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── HAS — Commission de la Transparence (avis médicaments) ──────────
    # ~500-800 avis/an. Enrichissement : scraping page HTML.
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081449",
        "label": "HAS — Commission de la Transparence (avis médicaments)",
        "source": "has_ct",
        "source_type": "recommandation",  # avis CT = recommandation (type déterminé par LLM)
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },

    # ── HAS — Avis dispositifs médicaux (CNEDIMTS) ──────────────────────
    # Admissions au remboursement, conditions utilisation.
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081446",
        "label": "HAS — Avis sur les dispositifs médicaux (CNEDIMTS)",
        "source": "has_dm",
        "source_type": "reglementaire",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── ANSM — Informations de sécurité (flux global) ────────────────────
    # Pharmacovigilance, retraits AMM, nouvelles CI, DHPC
    {
        "url": "https://ansm.sante.fr/rss/informations_securite",
        "label": "ANSM — Informations de sécurité (pharmacovigilance + DHPC)",
        "source": "ansm_securite",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens", "infirmiers"],
        "specialty_hint": "tous",
    },

    # ── ANSM — Sécurité médicaments uniquement ───────────────────────────
    {
        "url": "https://ansm.sante.fr/rss/informations_securite?produitsSante=medicaments",
        "label": "ANSM — Sécurité médicaments",
        "source": "ansm_securite_med",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },

    # ── ANSM — Sécurité dispositifs médicaux ─────────────────────────────
    # Retraits d'implants, alertes matériel d'injection, instruments chirurgicaux.
    {
        "url": "https://ansm.sante.fr/rss/informations_securite?produitsSante=dispositifs_medicaux",
        "label": "ANSM — Sécurité dispositifs médicaux",
        "source": "ansm_securite_dm",
        "source_type": "reglementaire",
        "audience": ["medecins", "infirmiers"],
        "specialty_hint": "tous",
    },

    # ── ANSM — Ruptures/tensions médicaments ─────────────────────────────
    {
        "url": "https://ansm.sante.fr/rss/disponibilite_produits_sante?produitsSante=medicaments",
        "label": "ANSM — Ruptures/tensions médicaments",
        "source": "ansm_ruptures_med",
        "source_type": "reglementaire",
        "audience": ["pharmaciens", "medecins"],
        "specialty_hint": "tous",
    },

    # ── ANSM — Disponibilité vaccins ─────────────────────────────────────
    {
        "url": "https://ansm.sante.fr/rss/disponibilite_produits_sante?produitsSante=vaccins",
        "label": "ANSM — Disponibilité vaccins",
        "source": "ansm_ruptures_vaccins",
        "source_type": "reglementaire",
        "audience": ["pharmaciens", "medecins"],
        "specialty_hint": "tous",
    },

    # ── Bulletins officiels ministères sociaux ────────────────────────────
    # Circulaires et instructions du ministère Santé hors JORF.
    {
        "url": "https://bulletins-officiels.social.gouv.fr/rss.xml",
        "label": "Bulletins officiels ministères sociaux",
        "source": "bo_social",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },

    # ── Santé publique France — Articles (BEH, alertes, épidémiologie) ───
    {
        "url": "https://www.santepubliquefrance.fr/rss/types-de-documents/article.xml",
        "label": "Santé publique France — Articles (BEH, alertes, épidémiologie)",
        "source": "spf_beh",
        "source_type": "reglementaire",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── CNOM — Ordre National des Médecins ────────────────────────────────
    # Déontologie, exercice libéral, responsabilité professionnelle.
    {
        "url": "https://www.conseil-national.medecin.fr/rss.xml",
        "label": "CNOM — Conseil National de l'Ordre des Médecins",
        "source": "cnom",
        "source_type": "reglementaire",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 7,
    },

    # ── Académie Nationale de Médecine ────────────────────────────────────
    {
        "url": "https://www.academie-medecine.fr/feed/",
        "label": "Académie Nationale de Médecine — Publications",
        "source": "academie_medecine",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── HAS — Décisions d'accès précoce (ex-ATU cohorte) ─────────────────
    # Priorité maximale : une décision d'accès précoce = le médecin peut
    # prescrire un médicament innovant sans AMM dès maintenant, pour une
    # pathologie grave sans alternative. Très actif (~3-5 décisions/semaine).
    # Exemples : téplizumab (DT1), sépiaptérine (phénylcétonurie), évinacumab.
    # Couvre toutes spécialités : oncologie, maladies rares, immuno, pédiatrie.
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3298842",
        "label": "HAS — Décisions d'accès précoce (ex-ATU — médicaments innovants)",
        "source": "has_acces_precoces",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },

    # ── HAS — Bulletin officiel ───────────────────────────────────────────
    # Toutes les décisions formelles HAS : accès précoces, avis vaccins,
    # décisions de certification, avis CEESP. Overlap partiel avec has_rbp
    # et has_ct — le pipeline déduplique par URL. Apporte les avis formels
    # (numérotés "Décision n°...") non présents dans les autres flux.
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3113093",
        "label": "HAS — Bulletin officiel (décisions et avis formels)",
        "source": "has_bo",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
        "min_score_hint": 6,
    },

    # ── ANSM — Actualités (points d'information, bilans, communiqués) ─────
    # Contient des points d'information importants sur des médicaments ou
    # des signaux de pharmacovigilance, mais aussi du bruit institutionnel
    # (bilans financiers, RH). min_score élevé pour filtrer le bruit.
    {
        "url": "https://ansm.sante.fr/rss/actualites",
        "label": "ANSM — Actualités (points d'information, communiqués)",
        "source": "ansm_actualites",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
        "min_score_hint": 8,
    },
]


# =============================================================================
# SECTION 2 — SOCIÉTÉS SAVANTES FRANÇAISES
# Audit RSS complet mars 2026 : 25 flux valides.
# ❌ Sans RSS : SFH, SFR, SFO, SOFCOT, SOFMER, SFMV, SFPathol, SFCP,
#              FFMKR, CNSF, SFPédiatrie, SFNN, SFSP, SFSCMFCO, SFDermato
# =============================================================================

FR_SOCIETIES_FEEDS: list[dict] = [

    # ── Médecine générale ─────────────────────────────────────────────────
    {
        "url": "https://www.cnge.fr/feed",
        "label": "CNGE — Collège National des Généralistes Enseignants",
        "source": "cnge",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-generale",
    },

    # ── Médecine interne ──────────────────────────────────────────────────
    {
        "url": "https://www.snfmi.org/rss.xml",
        "label": "SNFMI — Société Nationale Française de Médecine Interne",
        "source": "snfmi",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-interne",
    },

    # ── Cardiologie / HTA ─────────────────────────────────────────────────
    {
        "url": "https://sfhta.eu/feed",
        "label": "SFHTA — Société Française d'Hypertension Artérielle",
        "source": "sfhta",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },

    # ── Anesthésiologie-Réanimation ───────────────────────────────────────
    {
        "url": "https://sfar.org/feed",
        "label": "SFAR — Société Française d'Anesthésie et de Réanimation",
        "source": "sfar",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesiologie",
    },

    # ── Neurologie ────────────────────────────────────────────────────────
    {
        "url": "https://www.sf-neuro.org/feed",
        "label": "SFN — Société Française de Neurologie",
        "source": "sfn",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },

    # ── Psychiatrie ───────────────────────────────────────────────────────
    # sfpsy.org = Société Française de Psychologie (≠ psychiatrie médicale) — URL corrigée
    # AFPBN = Association Française de Psychiatrie Biologique et Neuropsychopharmacologie
    # FFP (Fédération Française de Psychiatrie) : pas de RSS accessible
    {
        "url": "https://www.afpbn.org/feed/",
        "label": "AFPBN — Psychiatrie biologique et neuropsychopharmacologie",
        "source": "sfpsychiatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
    },

    # ── Gastroentérologie ─────────────────────────────────────────────────
    {
        "url": "https://www.snfge.org/rss.xml",
        "label": "SNFGE — Société Nationale Française de Gastro-Entérologie",
        "source": "snfge",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
    },

    # ── Hépatologie ───────────────────────────────────────────────────────
    {
        "url": "https://afef.asso.fr/feed",
        "label": "AFEF — Association Française pour l'Étude du Foie",
        "source": "afef",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
    },

    # ── Pneumologie ───────────────────────────────────────────────────────
    # SPLF désactivé : splf.fr/feed retourne des pages de centres de recherche
    # (CRCTB, INSERM, CNRS), pas d'actualités cliniques. Aucun sous-feed actif.
    # Pneumologie couverte par ERS (EU_FEEDS) + PubMed (pubmed_chest, pubmed_thorax_bts).
    # {
    #     "url": "https://splf.fr/feed",
    #     "label": "SPLF — Société de Pneumologie de Langue Française",
    #     "source": "splf",
    #     "source_type": "recommandation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "pneumologie",
    # },

    # ── Endocrinologie ────────────────────────────────────────────────────
    {
        "url": "https://www.sfendocrino.org/feed/",
        "label": "SFE — Société Française d'Endocrinologie",
        "source": "sfendocrino",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
    },

    # ── Diabétologie ──────────────────────────────────────────────────────
    # SFD désactivé : rss.xml = 2 items (dernier : 2014), aucun feed alternatif actif.
    # Diabétologie couverte par PubMed (pubmed_diabetes_care, pubmed_diabetologia, etc.)
    # {
    #     "url": "https://www.sfdiabete.org/rss.xml",
    #     "label": "SFD — Société Francophone du Diabète",
    #     "source": "sfdiabete",
    #     "source_type": "recommandation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "endocrinologie",
    # },

    # ── Rhumatologie ──────────────────────────────────────────────────────
    {
        "url": "https://larhumatologie.fr/feed",
        "label": "SFRhumato — Société Française de Rhumatologie",
        "source": "sfrhumato",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
    },

    # ── ORL ───────────────────────────────────────────────────────────────
    {
        "url": "https://www.sforl.org/feed",
        "label": "SFORL — Société Française d'ORL et de Chirurgie de la Face et du Cou",
        "source": "sforl",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
    },

    # ── Urologie ──────────────────────────────────────────────────────────
    {
        "url": "https://urofrance.org/feed",
        "label": "AFU — Association Française d'Urologie",
        "source": "afu",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "urologie",
    },

    # ── Gériatrie ─────────────────────────────────────────────────────────
    {
        "url": "https://sfgg.org/feed",
        "label": "SFGG — Société Française de Gériatrie et Gérontologie",
        "source": "sfgg",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "geriatrie",
    },

    # ── Gynécologie-obstétrique ───────────────────────────────────────────
    {
        "url": "https://www.cngof.fr/feed",
        "label": "CNGOF — Collège National des Gynécologues et Obstétriciens Français",
        "source": "cngof_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
    },

    # ── Néphrologie ───────────────────────────────────────────────────────
    # SFNDT désactivé : derniers items en 2022, tous feeds alternatifs retournent 404.
    # Néphrologie couverte par PubMed (pubmed_jasn, pubmed_kidney_int, etc.) + ERA (EU_FEEDS).
    # {
    #     "url": "https://www.sfndt.org/actualites/feed",
    #     "label": "SFNDT — Société Francophone de Néphrologie Dialyse et Transplantation",
    #     "source": "sfndt",
    #     "source_type": "recommandation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "nephrologie",
    # },

    # ── Chirurgie thoracique et cardio-vasculaire ─────────────────────────
    {
        "url": "https://www.sfctcv.org/feed",
        "label": "SFCTCV — Société Française de Chirurgie Thoracique et Cardio-Vasculaire",
        "source": "sfctcv",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-thoracique",
    },

    # ── Neurochirurgie ────────────────────────────────────────────────────
    {
        "url": "https://sfneurochirurgie.fr/feed/",
        "label": "SFNC — Société Française de Neurochirurgie",
        "source": "sfnc",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "neurochirurgie",
    },

    # ── Coloproctologie ───────────────────────────────────────────────────
    {
        "url": "https://www.snfcp.org/feed/",
        "label": "SNFCP — Société Nationale Française de Coloproctologie",
        "source": "snfcp",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
    },

    # ── Microbiologie / Infectiologie ─────────────────────────────────────
    {
        "url": "https://www.sfm-microbiologie.org/feed/",
        "label": "SFM — Société Française de Microbiologie",
        "source": "sfm_microbiologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
    },

    # ── Chirurgie vasculaire ───────────────────────────────────────────────
    {
        "url": "https://www.vasculaire.com/rss.xml",
        "label": "SCVE — Société de Chirurgie Vasculaire et Endovasculaire (bulletin officiel)",
        "source": "sfcv",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 6,
    },

    # ── Médecine du sport ─────────────────────────────────────────────────
    # SFMS désactivé : sfms.fr = Société Française de Médecine Sexuelle (≠ du sport).
    # La vraie SFMS sport (sfms.asso.fr) n'a pas de RSS accessible.
    # {
    #     "url": "https://www.sfms.fr/feed/",
    #     "label": "SFMS — Société Française de Médecine du Sport",
    #     "source": "sfms",
    #     "source_type": "recommandation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "medecine-generale",
    # },

    # ── Alcoologie ────────────────────────────────────────────────────────
    {
        "url": "https://sfalcoologie.fr/feed/",
        "label": "SFA — Société Française d'Alcoologie",
        "source": "sfalcoologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-interne",
    },

    # ── Médecine nucléaire ────────────────────────────────────────────────
    {
        "url": "https://www.cnp-mn.fr/feed/",
        "label": "SFMN — Société Française de Médecine Nucléaire",
        "source": "sfmn",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
    },

    # ── Médecine d'urgence ────────────────────────────────────────────────
    {
        "url": "https://www.sfmu.org/full-rss.php",
        "label": "SFMU — Société Française de Médecine d'Urgence",
        "source": "sfmu",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },

    # ── Oncologie ─────────────────────────────────────────────────────────
    {
        "url": "https://www.afsos.org/feed/",
        "label": "AFSOS — Association Francophone pour les Soins Oncologiques de Support",
        "source": "afsos",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },

    # ── Infectiologie pédiatrique (GPIP) ─────────────────────────────────
    # Recommandations françaises de référence : antibiothérapies, méningites,
    # pneumonies, IU, scarlatine, sepsis néonatal.
    {
        "url": "https://gpip.fr/feed/",
        "label": "GPIP — Recommandations infectiologie pédiatrique française",
        "source": "gpip",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # ── Infirmiers ────────────────────────────────────────────────────────
    {
        "url": "https://www.sniil.fr/feed/",
        "label": "SNIIL — Syndicat National des Infirmières et Infirmiers Libéraux",
        "source": "sniil",
        "source_type": "recommandation",
        "audience": ["paramedical"],
        "specialty_hint": "infirmiers",
    },

    # ── Biologie médicale ─────────────────────────────────────────────────
    {
        "url": "https://sfbc-asso.fr/feed/",
        "label": "SFBC — Société Française de Biologie Clinique",
        "source": "sfbc",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "biologiste",
    },

    # ── Pharmacie ─────────────────────────────────────────────────────────
    {
        "url": "https://www.fspf.fr/feed/",
        "label": "FSPF — Fédération des Syndicats Pharmaceutiques de France",
        "source": "fspf",
        "source_type": "recommandation",
        "audience": ["pharmacien"],
        "specialty_hint": "pharmacien",
    },
]


# =============================================================================
# SECTION 3 — AGENCES & SOCIÉTÉS SAVANTES EUROPÉENNES
# EMA, ECDC, ESC (scraping), ESMO, EULAR, ERS, EASL, EAU (scraping)…
# Audit RSS mars 2026 : 26 flux actifs + 18 sources en scraping HTML (EU_WEB_SOURCES)
# =============================================================================

EU_FEEDS: list[dict] = [

    # ── EMA — European Medicines Agency ──────────────────────────────────
    {
        "url": "https://www.ema.europa.eu/en/news.xml",
        "label": "EMA — News et alertes (retraits AMM, nouvelles mesures sécurité)",
        "source": "ema_news",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },
    {
        "url": "https://www.ema.europa.eu/en/scientific-guidelines.xml",
        "label": "EMA — Scientific Guidelines (standards évaluation médicaments)",
        "source": "ema_guidelines",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },
    {
        "url": "https://www.ema.europa.eu/en/human-medicine-new.xml",
        "label": "EMA — Nouvelles AMM européennes (médicaments humains)",
        "source": "ema_new_medicines",
        "source_type": "innovation",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },

    # ── ECDC — European Centre for Disease Prevention and Control ─────────
    {
        "url": "https://www.ecdc.europa.eu/en/taxonomy/term/1295/feed",
        "label": "ECDC — Risk Assessments (évaluations risque épidémique)",
        "source": "ecdc_risk",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens", "infirmiers"],
        "specialty_hint": "infectiologie",
    },
    {
        "url": "https://www.ecdc.europa.eu/en/taxonomy/term/1301/feed",
        "label": "ECDC — Guidance (recommandations prévention, contrôle infections)",
        "source": "ecdc_guidance",
        "source_type": "recommandation",
        "audience": ["medecins", "pharmaciens", "infirmiers"],
        "specialty_hint": "infectiologie",
    },
    {
        "url": "https://www.ecdc.europa.eu/en/taxonomy/term/1505/feed",
        "label": "ECDC — CDTR (Communicable Disease Threats Report, hebdo)",
        "source": "ecdc_cdtr",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
    },

    # ── Sociétés savantes européennes — RSS actifs ────────────────────────

    # Oncologie — ESMO
    {
        "url": "https://www.esmo.org/rss/feed/esmo-news",
        "label": "ESMO — European Society for Medical Oncology (news + guidelines)",
        "source": "esmo",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },

    # Pneumologie — ERS
    {
        "url": "https://www.ersnet.org/feed/",
        "label": "ERS — European Respiratory Society (guidelines + news)",
        "source": "ers",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
    },

    # Hépatologie — EASL
    {
        "url": "https://easl.eu/feed/",
        "label": "EASL — European Association for Study of the Liver (guidelines)",
        "source": "easl",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
    },

    # Réanimation — ESICM
    {
        "url": "https://www.esicm.org/feed/",
        "label": "ESICM — European Society of Intensive Care Medicine (sepsis, ARDS…)",
        "source": "esicm",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesiologie",
    },

    # AVC — ESO
    {
        "url": "https://eso-stroke.org/feed",
        "label": "ESO — European Stroke Organisation (guidelines AVC, thrombolyse)",
        "source": "eso_stroke",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },

    # Dermatologie — EADV
    {
        "url": "https://www.eadv.org/feed",
        "label": "EADV — European Academy of Dermatology and Venereology (guidelines)",
        "source": "eadv",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
    },

    # Gynécologie-oncologie — ESGO
    {
        "url": "https://www.esgo.org/feed",
        "label": "ESGO — European Society of Gynaecological Oncology (guidelines)",
        "source": "esgo",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
    },

    # Orthopédie — EFORT
    {
        "url": "https://efort.org/feed",
        "label": "EFORT — European Federation of Orthopaedic Associations (standards)",
        "source": "efort",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
    },

    # Psychiatrie — EPA
    {
        "url": "https://www.europsy.net/feed",
        "label": "EPA — European Psychiatric Association (guidance psychiatrie)",
        "source": "epa_psychiatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
    },

    # Anesthésiologie — ESAIC
    {
        "url": "https://esaic.org/feed",
        "label": "ESAIC — European Society of Anaesthesiology and Intensive Care",
        "source": "esaic",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesiologie",
    },

    # Chirurgie cardiaque — EACTS
    {
        "url": "https://www.eacts.org/feed",
        "label": "EACTS — European Association for Cardio-Thoracic Surgery (joint ESC)",
        "source": "eacts",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-cardiaque",
    },

    # Gériatrie — IAGG-ER
    {
        "url": "https://www.iagg.info/feed",
        "label": "IAGG-ER — International Association of Gerontology (branche Europe)",
        "source": "iagg_geriatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "geriatrie",
    },

    # Médecine physique — ESPRM
    {
        "url": "https://www.esprm.net/feed",
        "label": "ESPRM — European Society Physical and Rehabilitation Medicine",
        "source": "esprm",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-physique",
    },

    # Pédiatrie — EAP
    {
        "url": "https://www.eapaediatrics.eu/feed",
        "label": "EAP — European Academy of Paediatrics (guidance pédiatrie)",
        "source": "eap_pediatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # Radiologie — ESR
    {
        "url": "https://www.myesr.org/feed",
        "label": "ESR — European Society of Radiology (standards imagerie, iGuide)",
        "source": "esr_radiologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
    },

    # Orthodontie — EOS/EJO : OUP Cloudflare WAF bloque feedparser (HTTP 404, HTML retourné).
    # Pas d'alternative RSS identifiée (EJO exclusivement sur OUP).
    # {
    #     "url": "https://academic.oup.com/rss/content/journal/ejo",
    #     "label": "EOS/EJO — European Journal of Orthodontics (orthodontie)",
    #     "source": "eos_ejo",
    #     "source_type": "recommandation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "orthodontiste",
    # },

    # Rhumatologie — ARD/EULAR
    {
        "url": "https://ard.bmj.com/rss/current.xml",
        "label": "ARD/EULAR — Annals of Rheumatic Diseases (recommendations EULAR)",
        "source": "ard_eular",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
    },

    # Chirurgie pédiatrique — EUPSA/EJPS
    {
        "url": "https://link.springer.com/search.rss?query=pediatric+surgery&search-within=Journal&facet-journal-id=383",
        "label": "EJPS — European Journal of Pediatric Surgery via Springer RSS (chirurgie pédiatrique)",
        "source": "eupsa_ejps",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-pediatrique",
    },
]


# =============================================================================
# SECTION 4 — JOURNAUX ACADÉMIQUES INTERNATIONAUX
# JAMA Network, NEJM, Lancet, BMJ, journaux spécialisés (IF 3–65)
# et journaux paramédicaux de référence.
# =============================================================================

JOURNALS_FEEDS: list[dict] = [

    # ── JAMA Network ──────────────────────────────────────────────────────
    # JAMA général (67.xml) fonctionne. Specialty (68-78.xml) = endpoints supprimés
    # (HTTP 404 confirmé feedparser avr. 2026). Remplacés par pubmed_collector :
    # Derm → pubmed_jama_derm | Ophtalmo → pubmed_jama_ophthalmol
    # ORL → pubmed_jama_otolaryngol | Pédia → pubmed_jama_peds
    # Psy → pubmed_jama_psychiatry | Chir → pubmed_jama_surgery
    # Cardio / Internal Med / Neuro / Onco / Network Open : pas d'équivalent PubMed → à créer si besoin
    {
        "url": "https://jamanetwork.com/rss/site_3/67.xml",
        "label": "JAMA — Journal général (toutes spécialités)",
        "source": "jama",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── Grands journaux généralistes ──────────────────────────────────────
    {
        "url": "https://www.nejm.org/action/showFeed?jc=nejm&type=etoc&feed=rss",
        "label": "New England Journal of Medicine (NEJM)",
        "source": "nejm",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/lancet_current.xml",
        "label": "The Lancet",
        "source": "lancet",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
    # BMJ général — feeds.bmj.com mort (DNS/connexion refused depuis avr. 2026)
    # www.bmj.com bloque curl + feedparser (Cloudflare WAF). Couvert par sous-journaux BMJ
    # specialty (heart, thorax, gut, ard, jnnp, adc) et par pubmed_collector.
    # {
    #     "url": "https://feeds.bmj.com/bmj/current.rss",
    #     "label": "BMJ — British Medical Journal",
    #     "source": "bmj",
    #     "source_type": "innovation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "tous",
    # },
    {
        "url": "https://www.nature.com/nm.rss",
        "label": "Nature Medicine — Recherche translationnelle",
        "source": "nature_medicine",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── Lancet specialty — 10 journaux spécialisés ────────────────────────
    {
        "url": "https://www.thelancet.com/rssfeed/laneur_current.xml",
        "label": "Lancet Neurology (IF ~57)",
        "source": "lancet_neurology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },
    {
        "url": "https://rss.sciencedirect.com/publication/science/14702045",
        "label": "Lancet Oncology (IF ~51)",
        "source": "lancet_oncology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/lanpsy_current.xml",
        "label": "Lancet Psychiatry (IF ~65)",
        "source": "lancet_psychiatry",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/laninf_current.xml",
        "label": "Lancet Infectious Diseases (IF ~40)",
        "source": "lancet_infect_dis",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/landia_current.xml",
        "label": "Lancet Diabetes & Endocrinology (IF ~44)",
        "source": "lancet_diab_endo_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/lanhae_current.xml",
        "label": "Lancet Haematology (IF ~27)",
        "source": "lancet_haematol",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
    },
    {
        "url": "https://rss.sciencedirect.com/publication/science/24681253",
        "label": "Lancet Gastroenterology & Hepatology (IF ~35)",
        "source": "lancet_gastro_hepatol",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/lanres_current.xml",
        "label": "Lancet Respiratory Medicine (IF ~38)",
        "source": "lancet_respir_med",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/lanrhe_current.xml",
        "label": "Lancet Rheumatology (IF ~25)",
        "source": "lancet_rheumatol",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
    },
    {
        "url": "https://www.thelancet.com/rssfeed/eclinm_current.xml",
        "label": "eClinicalMedicine (Lancet open-access — toutes spécialités)",
        "source": "eclinmedicine",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # ── BMJ specialty — 6 journaux ────────────────────────────────────────
    {
        "url": "https://heart.bmj.com/rss/current.xml",
        "label": "Heart (BMJ) — British Cardiac Society (IF ~15)",
        "source": "bmj_heart",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },
    {
        "url": "https://thorax.bmj.com/rss/current.xml",
        "label": "Thorax (BMJ) — British Thoracic Society (IF ~10)",
        "source": "bmj_thorax",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
    },
    {
        "url": "https://gut.bmj.com/rss/current.xml",
        "label": "Gut (BMJ) — British Society of Gastroenterology (IF ~24)",
        "source": "bmj_gut",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
    },
    {
        "url": "https://ard.bmj.com/rss/current.xml",
        "label": "Annals of the Rheumatic Diseases (ARD/EULAR flagship, IF ~27)",
        "source": "bmj_ard",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
    },
    {
        "url": "https://jnnp.bmj.com/rss/current.xml",
        "label": "JNNP — Journal of Neurology, Neurosurgery & Psychiatry (BMJ, IF ~9)",
        "source": "bmj_jnnp",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },
    {
        "url": "https://adc.bmj.com/rss/current.xml",
        "label": "Archives of Disease in Childhood (ADC/RCPCH, BMJ, IF ~5)",
        "source": "bmj_adc",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # ── Journaux spécialisés par spécialité ───────────────────────────────

    # Cardiologie
    {
        "url": "https://www.ahajournals.org/action/showFeed?jc=circ&type=etoc&feed=rss",
        "label": "Circulation (AHA, IF ~35)",
        "source": "circulation_aha",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },
    {
        "url": "https://www.ahajournals.org/action/showFeed?jc=jaha&type=etoc&feed=rss",
        "label": "JAHA — Journal of the American Heart Association (IF ~5)",
        "source": "jaha",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },
    {
        "url": "https://rss.sciencedirect.com/publication/science/07351097",
        "label": "JACC — Journal of the American College of Cardiology (IF ~24)",
        "source": "jacc_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },

    # Neurologie
    {
        "url": "https://www.neurology.org/action/showFeed?jc=wnl&type=etoc&feed=rss",
        "label": "Neurology (AAN, IF ~9)",
        "source": "neurology_aan",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },
    {
        "url": "https://onlinelibrary.wiley.com/feed/15318249/most-recent",
        "label": "Annals of Neurology (ANA/Wiley, IF ~11)",
        "source": "ann_neurol",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },
    {
        "url": "https://www.ahajournals.org/action/showFeed?jc=str&type=etoc&feed=rss",
        "label": "Stroke (AHA/ASA, IF ~8) — AVC, thrombectomie",
        "source": "stroke_aha",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },

    # Oncologie
    {
        "url": "https://ascopubs.org/action/showFeed?jc=jco&type=etoc&feed=rss",
        "label": "Journal of Clinical Oncology (JCO/ASCO, IF ~45)",
        "source": "jco_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },
    {
        "url": "https://www.annalsofoncology.org/action/showFeed?jc=annonc&type=etoc&feed=rss",
        "label": "Annals of Oncology (ESMO flagship, IF ~51)",
        "source": "ann_oncol_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },

    # Hématologie
    {
        "url": "https://rss.sciencedirect.com/publication/science/00064971",
        "label": "Blood (ASH/Elsevier, IF ~25)",
        "source": "blood_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
    },
    {
        "url": "https://onlinelibrary.wiley.com/feed/10968652/most-recent",
        "label": "American Journal of Hematology (Wiley, IF ~12)",
        "source": "am_j_hematol",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
    },
    {
        "url": "https://www.nature.com/leu.rss",
        "label": "Leukemia (Nature portfolio, IF ~12)",
        "source": "leukemia_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
    },

    # Infectiologie
    {
        "url": "https://tools.cdc.gov/api/v2/resources/media/404952.rss",
        "label": "Emerging Infectious Diseases (CDC, IF ~12)",
        "source": "eid_cdc",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
    },

    # Néphrologie
    {
        "url": "https://rss.sciencedirect.com/publication/science/00852538",
        "label": "Kidney International (ISN/Elsevier, IF ~14)",
        "source": "kidney_int_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "nephrologie",
    },

    # Ophtalmologie
    {
        "url": "https://rss.sciencedirect.com/publication/science/01616420",
        "label": "Ophthalmology (AAO/Elsevier, IF ~14)",
        "source": "ophthalmology_aao",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
    },
    {
        "url": "https://bjo.bmj.com/rss/current.xml",
        "label": "British Journal of Ophthalmology (BMJ, IF ~5)",
        "source": "bjo_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
    },

    # ORL
    {
        "url": "https://journals.sagepub.com/action/showFeed?jc=oto&type=axatoc&feed=rss",
        "label": "Otolaryngology — Head & Neck Surgery (AAO-HNS/SAGE, IF ~3)",
        "source": "otohns_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
    },
    {
        "url": "https://aao-hnsfjournals.onlinelibrary.wiley.com/feed/15314995/most-recent",
        "label": "The Laryngoscope (ALA/Wiley, IF ~3)",
        "source": "laryngoscope_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
    },
    {
        "url": "https://onlinelibrary.wiley.com/feed/10970347/most-recent",
        "label": "Head & Neck (Wiley, IF ~3) — chirurgie cervico-faciale & oncologie",
        "source": "head_neck_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
    },

    # Médecine d'urgences
    {
        "url": "https://www.annemergmed.com/action/showFeed?jc=ymem&type=etoc&feed=rss",
        "label": "Annals of Emergency Medicine (ACEP flagship, IF ~9)",
        "source": "ann_emerg_med_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },
    {
        "url": "https://emj.bmj.com/rss/current.xml",
        "label": "Emergency Medicine Journal (RCEM/BMJ, IF ~4)",
        "source": "emj_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },
    {
        "url": "https://rss.sciencedirect.com/publication/science/03009572",
        "label": "Resuscitation (ERC/AHA/Elsevier, IF ~6) — RCP & soins post-arrêt",
        "source": "resuscitation_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },

    # Radiologie
    {
        "url": "https://link.springer.com/search.rss?facet-journal-id=330&query=",
        "label": "European Radiology (Springer/ESR, IF ~7)",
        "source": "eur_radiol_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
    },

    # Dermatologie
    {
        "url": "https://rss.sciencedirect.com/publication/science/01909622",
        "label": "JAAD — Journal American Academy of Dermatology (IF ~13)",
        "source": "jaad_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
    },
    {
        "url": "https://onlinelibrary.wiley.com/feed/13652133/most-recent",
        "label": "British Journal of Dermatology (BAD/Wiley, IF ~11)",
        "source": "bjd_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
    },

    # Endocrinologie
    {
        "url": "https://care.diabetesjournals.org/rss/current.xml",
        "label": "Diabetes Care (ADA, IF ~16)",
        "source": "diabetes_care_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
    },

    # Rhumatologie
    {
        "url": "https://onlinelibrary.wiley.com/feed/23265205/most-recent",
        "label": "Arthritis & Rheumatology (ACR flagship/Wiley, IF ~14)",
        "source": "arthritis_rheumatol_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
    },

    # Gériatrie
    {
        "url": "https://agsjournals.onlinelibrary.wiley.com/feed/15325415/most-recent",
        "label": "Journal of the American Geriatrics Society (AGS/Wiley, IF ~7)",
        "source": "jags_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "geriatrie",
    },

    # Gynécologie
    {
        "url": "https://rss.sciencedirect.com/publication/science/00029378",
        "label": "AJOG — American Journal of Obstetrics & Gynecology (Elsevier, IF ~10)",
        "source": "ajog_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
    },

    # Médecine interne
    {
        "url": "https://www.acpjournals.org/action/showFeed?jc=aim&type=etoc&feed=rss",
        "label": "Annals of Internal Medicine (ACP, IF ~51)",
        "source": "ann_intern_med_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-interne",
    },

    # Médecine générale
    {
        "url": "https://www.cmaj.ca/rss/current.xml",
        "label": "CMAJ — Canadian Medical Association Journal (IF ~8)",
        "source": "cmaj_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-generale",
    },
    {
        "url": "https://bjgp.org/rss/current.xml",
        "label": "BJGP — British Journal of General Practice (RCGP, IF ~5)",
        "source": "bjgp_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-generale",
    },

    # Pneumologie
    {
        "url": "https://journal.chestnet.org/action/showFeed?jc=chest&type=etoc&feed=rss",
        "label": "Chest (ACCP, IF ~9) — pneumologie, soins intensifs",
        "source": "chest_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
    },

    # Chirurgie thoracique
    {
        "url": "https://rss.sciencedirect.com/publication/science/15560864",
        "label": "Journal of Thoracic Oncology (IASLC, IF ~20) — cancer bronchique",
        "source": "jto_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-thoracique",
    },

    # Chirurgie vasculaire
    {
        "url": "https://rss.sciencedirect.com/publication/science/07415214",
        "label": "Journal of Vascular Surgery (SVS/Elsevier) — RSS direct",
        "source": "jvs_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
    },

    # Médecine physique & réadaptation
    {
        "url": "https://rss.sciencedirect.com/publication/science/00039993",
        "label": "Archives of Physical Medicine and Rehabilitation (ACRM/Elsevier, IF ~4)",
        "source": "arch_pmr_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-physique",
    },
    {
        "url": "https://onlinelibrary.wiley.com/feed/19341563/most-recent",
        "label": "PM&R Journal (AAPM&R/Wiley, IF ~3)",
        "source": "pmrj_rss",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-physique",
    },

    # ── Sources paramédicales ─────────────────────────────────────────────

    # Biologie médicale
    # Clinical Chemistry (OUP/AACC) : Cloudflare WAF bloque feedparser (HTTP 404, HTML retourné)
    # Couvert par pubmed_clin_chem dans pubmed_collector.
    # {
    #     "url": "https://academic.oup.com/rss/site_5278/advancepub.xml",
    #     "label": "Clinical Chemistry — Biologie médicale (AACC, Oxford)",
    #     "source": "clinical_chemistry",
    #     "source_type": "innovation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "biologiste",
    # },

    # Kinésithérapie
    # PTJ (OUP/APTA) : même blocage Cloudflare WAF que Clinical Chemistry.
    # Couvert par sources PubMed kinésithérapie dans pubmed_collector.
    # {
    #     "url": "https://academic.oup.com/rss/site_5305/advancepub.xml",
    #     "label": "Physical Therapy Journal (PTJ/APTA, Oxford)",
    #     "source": "ptj_kine",
    #     "source_type": "innovation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "kinesitherapie",
    # },

    # Sage-femme
    {
        "url": "https://obgyn.onlinelibrary.wiley.com/feed/14710528/most-recent",
        "label": "BJOG — British Journal of Obstetrics and Gynaecology (Wiley/RCOG)",
        "source": "bjog",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "sage-femme",
    },

    # Pharmacien
    {
        "url": "https://ascpt.onlinelibrary.wiley.com/feed/15326535/most-recent",
        "label": "Clinical Pharmacology & Therapeutics (Wiley/ASCPT)",
        "source": "cpt_pharmacol",
        "source_type": "innovation",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "pharmacien",
    },
    {
        "url": "https://bpspubs.onlinelibrary.wiley.com/feed/13652125/most-recent",
        "label": "British Journal of Clinical Pharmacology (BPS/Wiley, IF ~4)",
        "source": "br_j_clin_pharm_rss",
        "source_type": "innovation",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "pharmacien",
    },
    {
        "url": "https://journals.sagepub.com/action/showFeed?jc=aopa&type=etoc&feed=rss",
        "label": "Annals of Pharmacotherapy (SAGE, IF ~4)",
        "source": "ann_pharmacother_rss",
        "source_type": "innovation",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "pharmacien",
    },

    # Dentiste / Orthodontiste
    {
        "url": "https://journals.sagepub.com/action/showFeed?jc=jdrb&type=axatoc&feed=rss",
        "label": "Journal of Dental Research (JDR/IADR, SAGE)",
        "source": "jdr_dental",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "dentiste",
    },

    # Infirmiers
    {
        "url": "https://onlinelibrary.wiley.com/feed/13652648/most-recent",
        "label": "Journal of Advanced Nursing (JAN/Wiley)",
        "source": "jan_nursing",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "infirmiers",
    },

    # Archives de cardiologie française (SFC/SFCTCV)
    {
        "url": "https://rss.sciencedirect.com/publication/science/18752136",
        "label": "Archives of Cardiovascular Diseases (ACV) — journal officiel SFC/SFCTCV",
        "source": "arch_cardiovasc_dis",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-cardiaque",
    },
]


# =============================================================================
# SECTION 5 — PRESSE CLINIQUE PRATICIEN
# Journalistes médicaux, comptes-rendus de congrès, nouvelles guidelines,
# actualités thérapeutiques — rédigés POUR le praticien, pas pour le chercheur.
# Équivalent de Vascular Specialist / TCTMD pour chaque spécialité.
# ⚠️  Filtre LLM strict (min_score ≥ 7-8) : bruit élevé (brèves, politique
#     de santé, nominations, tribunes) à rejeter sans hésiter.
# =============================================================================

CLINICAL_PRESS_FEEDS: list[dict] = [

    # ── Chirurgie vasculaire ──────────────────────────────────────────────

    # SVS official newspaper : nouveaux dispositifs, résultats essais pivots,
    # guidelines SVS, congrès VAM/ESVS/VEITH/LINC.
    {
        "url": "https://vascularspecialistonline.com/feed/",
        "label": "Vascular Specialist (SVS official newspaper)",
        "source": "vascular_specialist",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },
    # Publication indépendante : congrès ESVS/CIRSE/LINC/ISET, dispositifs CE/FDA.
    {
        "url": "https://vascularnews.com/feed/",
        "label": "Vascular News",
        "source": "vascular_news",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },
    # Double spécialité vasculaire + cardiologie interventionnelle.
    # specialty_hint absent → LLM route par contenu.
    # DÉSACTIVÉ — tctmd.com retourne 403 pour tous les user-agents (anti-bot, 2025).
    # {
    #     "url": "https://www.tctmd.com/feed",
    #     "label": "TCTMD — Cardiovascular & Endovascular News (vasculaire + cardiac interventional)",
    #     "source": "tctmd",
    #     "source_type": "innovation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "tous",
    #     "min_score_hint": 8,
    # },
    {
        "url": "https://www.evtoday.com/rss",
        "label": "Endovascular Today — Peripheral & Endovascular",
        "source": "endovascular_today",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },

    # ── Presse médicale française généraliste ─────────────────────────────
    # Bruit très élevé → min_score élevé : seules les vraies nouvelles cliniques.
    {
        "url": "https://www.lequotidiendumedecin.fr/rss.xml",
        "label": "Le Quotidien du Médecin",
        "source": "quotidien_medecin",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 8,
    },
    {
        "url": "http://www.egora.fr/rss.xml",
        "label": "Egora — Presse médicale libérale",
        "source": "egora",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 9,
    },

    # ── Healio — 15 spécialités (vérifié avril 2026) ──────────────────────
    {
        "url": "https://www.healio.com/rss/cardiology",
        "label": "Healio Cardiology",
        "source": "healio_cardio",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/nephrology",
        "label": "Healio Nephrology",
        "source": "healio_nephro",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "nephrologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/infectious-disease",
        "label": "Healio Infectious Disease",
        "source": "healio_infect",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/rheumatology",
        "label": "Healio Rheumatology",
        "source": "healio_rhuma",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/endocrinology",
        "label": "Healio Endocrinology",
        "source": "healio_endo",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/ophthalmology",
        "label": "Healio Ophthalmology",
        "source": "healio_ophtalmo",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/gastroenterology",
        "label": "Healio Gastroenterology",
        "source": "healio_gastro",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/hematology-oncology",
        "label": "Healio Hematology-Oncology (mixte hémato + oncologie)",
        "source": "healio_hemato_onco",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/psychiatry",
        "label": "Healio Psychiatry",
        "source": "healio_psy",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/neurology",
        "label": "Healio Neurology",
        "source": "healio_neuro",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/orthopedics",
        "label": "Healio Orthopedics",
        "source": "healio_ortho",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/pulmonology",
        "label": "Healio Pulmonology",
        "source": "healio_pulmo",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/dermatology",
        "label": "Healio Dermatology",
        "source": "healio_derma",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/pediatrics",
        "label": "Healio Pediatrics",
        "source": "healio_pedia",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.healio.com/rss/geriatric-medicine",
        "label": "Healio Geriatric Medicine",
        "source": "healio_geria",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "geriatrie",
        "min_score_hint": 7,
    },

    # ── Sociétés savantes US — presse clinique ────────────────────────────
    {
        "url": "https://www.aans.org/rss",
        "label": "AANS Neurosurgeon News — neurochirurgie",
        "source": "aans_news",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurochirurgie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.aaos.org/rss",
        "label": "AAOS Now — chirurgie orthopédique",
        "source": "aaos_news",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.gastro.org/rss",
        "label": "AGA News — gastro-entérologie",
        "source": "aga_news",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.psychiatrictimes.com/rss",
        "label": "Psychiatric Times — presse clinique psychiatrie US",
        "source": "psychiatric_times",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
        "min_score_hint": 7,
    },
    {
        "url": "https://www.urologytimes.com/rss",
        "label": "Urology Times — presse clinique urologie US",
        "source": "urology_times",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "urologie",
        "min_score_hint": 7,
    },

    # ── ENTtoday (AAO-HNS) — ORL ──────────────────────────────────────────
    # Implants cochléaires, rhinosinusite (dupilumab, FESS), thyroïdectomie,
    # tumeurs cervico-faciales, SAOS. Congrès TRIO/AAO.
    {
        "url": "https://www.enttoday.org/feed/",
        "label": "ENTtoday (AAO-HNS) — presse clinique ORL",
        "source": "enttoday",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
        "min_score_hint": 7,
    },

    # ── MedPage Today — spécialités non couvertes par Healio ─────────────
    # ⚠️ min_score=8 : bruit US élevé (politique de santé, RFK Jr, CMS) à rejeter
    {
        "url": "https://www.medpagetoday.com/rss/obgyn.xml",
        "label": "MedPage Today OB/Gyn — gynécologie & obstétrique",
        "source": "medpage_obgyn",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
        "min_score_hint": 8,
    },
    {
        "url": "https://www.medpagetoday.com/rss/emergencymedicine.xml",
        "label": "MedPage Today Emergency Medicine — médecine d'urgences",
        "source": "medpage_emergency",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
        "min_score_hint": 8,
    },
    {
        "url": "https://www.medpagetoday.com/rss/anesthesiology.xml",
        "label": "MedPage Today Anesthesiology — anesthésiologie",
        "source": "medpage_anesthesiology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesiologie",
        "min_score_hint": 8,
    },
    {
        "url": "https://www.medpagetoday.com/rss/radiology.xml",
        "label": "MedPage Today Radiology — radiologie & imagerie",
        "source": "medpage_radiology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
        "min_score_hint": 8,
    },
    # Multi-spécialité chirurgicale (cardiaque, thoracique, plastique, etc.)
    # specialty_hint absent → LLM route par contenu
    {
        "url": "https://www.medpagetoday.com/rss/surgery.xml",
        "label": "MedPage Today Surgery — chirurgie (cardiaque, thoracique, etc.)",
        "source": "medpage_surgery",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 8,
    },
]


# =============================================================================
# SECTION 6 — SOURCES API (non-RSS)
# Registres réglementaires accessibles via API REST JSON.
# Collecte pilotée par collector.py selon le champ "collector".
# =============================================================================

API_SOURCES: list[dict] = [
    {
        "label": "FDA — PMA Class III (toutes spécialités — implants haut risque)",
        "source": "fda_pma",
        "collector": "fda_pma",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
    {
        "label": "FDA — 510(k) Class II (toutes spécialités — dispositifs médicaux)",
        "source": "fda_510k",
        "collector": "fda_510k",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
    {
        "label": "EUDAMED — Dispositifs médicaux CE Classe III (toutes spécialités)",
        "source": "eudamed",
        "collector": "eudamed",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
    # ── EMA DHPC — Dear Healthcare Professional Communications ───────────
    # Alertes de sécurité EMA : retrait, nouvelle CI, restriction d'indication,
    # erreur de conditionnement. Toujours actionnables — le praticien doit
    # modifier sa prescription immédiatement.
    #
    # Déployées uniquement sur les 6 spécialités les moins couvertes en
    # sources RSS/PubMed, où l'alerte EMA apporte une information unique.
    #
    # Chaque entrée filtre l'endpoint EMA DHPC par :
    #   atc_prefixes  : préfixes ATC (vide = pas de filtre ATC)
    #   mesh_keywords : mots-clés dans therapeutic_area_mesh (insensible casse)
    # ────────────────────────────────────────────────────────────────────

    # ── Biologie médicale ────────────────────────────────────────────────
    # Alertes produits de contraste (néphrotoxicité, gadolinium) +
    # radiopharmaceutiques. Les DHPC contrast/radio sont actionnables pour
    # tout biologiste ou radiologue prescripteur.
    # V08 : produits de contraste (iodés, gadolinium, échographie)
    # V09 : radiopharmaceutiques diagnostiques
    # V10 : radiopharmaceutiques thérapeutiques
    {
        "label": "EMA — DHPC biologie médicale (produits de contraste, radiopharmaceutiques)",
        "source": "ema_dhpc_biologie_medicale",
        "collector": "ema_dhpc",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "biologiste",
        "atc_prefixes": ["V08", "V09", "V10"],
        "mesh_keywords": ["contrast medium", "contrast agent", "radiopharmaceut", "diagnostic imaging"],
    },

    # ── Chirurgie pédiatrique ────────────────────────────────────────────
    # Pédiatrie = population, pas une classe ATC → filtre uniquement par MeSH.
    # DHPC actionnables : contre-indication pédiatrique nouvelle, alerte de
    # surdosage enfant, retrait d'un médicament en formulation pédiatrique.
    {
        "label": "EMA — DHPC chirurgie pédiatrique (alertes médicaments usage pédiatrique)",
        "source": "ema_dhpc_chirurgie_pediatrique",
        "collector": "ema_dhpc",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "chirurgie-pediatrique",
        "atc_prefixes": [],
        "mesh_keywords": ["pediatric", "paediatric", "child", "infant", "neonatal", "congenital"],
    },

    # ── Chirurgie plastique et reconstructrice ───────────────────────────
    # N01B   : anesthésiques locaux (lidocaïne, bupivacaïne — injections locales)
    # M03AX  : toxine botulinique (usages esthétiques + fonctionnels)
    # D03    : cicatrisants et kératolytiques
    {
        "label": "EMA — DHPC chirurgie plastique (anesthésiques locaux, toxine botulinique, cicatrisants)",
        "source": "ema_dhpc_chirurgie_plastique",
        "collector": "ema_dhpc",
        "source_type": "reglementaire",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-plastique",
        "atc_prefixes": ["N01B", "M03AX", "D03"],
        "mesh_keywords": ["wound healing", "reconstructive", "scar", "skin graft", "aesthetic"],
    },

    # ── Médecine physique et réadaptation ────────────────────────────────
    # M03AX  : toxine botulinique (spasticité — DHPC les plus impactants en MPR)
    # M03B   : myorelaxants centraux (baclofène, tizanidine)
    # N02A/B : antalgiques morphiniques + non-morphiniques (douleur chronique)
    {
        "label": "EMA — DHPC médecine physique (toxine botulinique, myorelaxants, antalgiques chroniques)",
        "source": "ema_dhpc_medecine_physique",
        "collector": "ema_dhpc",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "medecine-physique",
        "atc_prefixes": ["M03AX", "M03B", "N02A", "N02B"],
        "mesh_keywords": ["spasticity", "rehabilitation", "muscle spasm", "neuropathic pain", "chronic pain"],
    },

    # ── Ophtalmologie ────────────────────────────────────────────────────
    # S01 couvre l'intégralité des médicaments ophtalmiques :
    #   anti-infectieux, anti-inflammatoires, anti-VEGF (ranibizumab,
    #   aflibercept), anti-glaucome (prostaglandines, bêtabloquants oculaires),
    #   mydriatiques, anesthésiques oculaires, agents intravitréens.
    # DHPC actionnables : contamination lot anti-VEGF, erreur de dosage
    # intravitréen, retrait d'un collyre.
    {
        "label": "EMA — DHPC ophtalmologie (anti-VEGF, anti-glaucome, anti-infectieux oculaires)",
        "source": "ema_dhpc_ophtalmologie",
        "collector": "ema_dhpc",
        "source_type": "reglementaire",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "atc_prefixes": ["S01"],
        "mesh_keywords": ["eye disease", "ocular", "retinal", "macular", "glaucoma", "ophthalm", "intraocular", "uveitis"],
    },

    # ── Stomatologie / chirurgie maxillo-faciale ─────────────────────────
    # A01    : préparations stomatologiques (antiseptiques buccaux, fluorures)
    # N01B   : anesthésiques locaux dentaires (articaïne, lidocaïne)
    # M05B   : bisphosphonates et anti-RANKL → ostéonécrose de la mâchoire :
    #          DHPC bisphosphonates/denosumab = alerte de référence en stomatologie
    {
        "label": "EMA — DHPC stomatologie (bisphosphonates/ostéonécrose mâchoire, anesthésiques locaux)",
        "source": "ema_dhpc_stomatologie",
        "collector": "ema_dhpc",
        "source_type": "reglementaire",
        "audience": ["medecins"],
        "specialty_hint": "dentiste",
        "atc_prefixes": ["A01", "N01B", "M05B"],
        "mesh_keywords": ["dental", "oral", "jaw", "tooth", "osteonecrosis", "mandibular"],
    },
]


# =============================================================================
# POINT D'ENTRÉE UNIQUE
# Utilisé dans rss_collector.py : FEEDS = ALL_FEEDS
# =============================================================================

ALL_FEEDS: list[dict] = (
    FR_REGULATORY_FEEDS
    + FR_SOCIETIES_FEEDS
    + EU_FEEDS
    + JOURNALS_FEEDS
    + CLINICAL_PRESS_FEEDS
)


# =============================================================================
# SCRAPING HTML — sources sans flux RSS
# Utilisé dans web_scraper.py (importé comme EUROPE_WEB_SOURCES)
# =============================================================================

EU_WEB_SOURCES: list[dict] = [
    # PRIORITÉ 1 — Impact médico-légal maximal
    {
        "url": "https://www.escardio.org/Guidelines/Clinical-Practice-Guidelines",
        "source": "esc_guidelines",
        "label": "ESC — Clinical Practice Guidelines (cardiologie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
        "link_pattern": r"escardio\.org/",
        "exclude_pattern": r"(?i)/(the-esc|membership|education|congresses|about|advocacy|newsroom|journal|login|register)(/|$)",
    },
    {
        "url": "https://www.eular.org/recommendations-home",
        "source": "eular_recommendations",
        "label": "EULAR — Recommendations (rhumatologie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
        "link_pattern": r"eular\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|funding|jobs|contact|news|press)(/|$)",
    },
    {
        "url": "https://uroweb.org/guidelines",
        "source": "eau_guidelines",
        "label": "EAU — Guidelines (urologie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "urologie",
        "link_pattern": r"uroweb\.org/guideline",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|education|contact|news|jobs)(/|$)",
    },
    {
        "url": "https://www.escmid.org/guidelines-journals/guidelines/",
        "source": "escmid_guidelines",
        "label": "ESCMID — Guidelines (infectiologie, antibiothérapie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
        "link_pattern": r"escmid\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|education|contact|news|jobs|grants)(/|$)",
    },
    # PRIORITÉ 2 — Spécialités majeures
    {
        "url": "https://www.ean.org/research/ean-guidelines",
        "source": "ean_guidelines",
        "label": "EAN — Guidelines (neurologie : SEP, Parkinson, épilepsie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
        "link_pattern": r"ean\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|careers)(/|$)",
    },
    {
        "url": "https://ecco-ibd.eu/publications/guidelines",
        "source": "ecco_guidelines",
        "label": "ECCO — Guidelines (Crohn, RCH, MICI)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
        "link_pattern": r"ecco-ibd\.eu/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|grants)(/|$)",
    },
    {
        "url": "https://ehaweb.org/resources/guidelines/",
        "source": "eha_guidelines",
        "label": "EHA — Clinical Practice Guidelines (hématologie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
        "link_pattern": r"ehaweb\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|grants|jobs)(/|$)",
    },
    {
        "url": "https://www.easd.org/resources/tools/guidelines.html",
        "source": "easd_guidelines",
        "label": "EASD — Guidelines (diabète, consensus EASD/ADA)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
        "link_pattern": r"easd\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|annual)(/|$)",
    },
    {
        "url": "https://www.ese-hormones.org/publications/guidelines/",
        "source": "ese_guidelines",
        "label": "ESE — Guidelines (endocrinologie : thyroïde, surrénales, hypophyse)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
        "link_pattern": r"ese-hormones\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|jobs)(/|$)",
    },
    {
        "url": "https://www.era-online.org/guidelines/",
        "source": "era_guidelines",
        "label": "ERA — Practice Guidelines (néphrologie : IRC, dialyse, transplantation)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "nephrologie",
        "link_pattern": r"era-online\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|education)(/|$)",
    },
    # Gastroentérologie complément
    # UEG désactivé : toutes les URLs retournent 404 (site restructuré).
    # Gastro couverte par ECCO, ESGE, EASL, UEG PubMed.
    {
        "url": "https://www.esge.com/publications/guidelines/",
        "source": "esge_guidelines",
        "label": "ESGE — Eur. Society Gastrointestinal Endoscopy (guidelines endoscopie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
        "link_pattern": r"esge\.com/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|education|awards|foundation)(/|$)",
    },
    # Médecine d'urgence
    {
        "url": "https://eusem.org/research/guidelines",
        "source": "eusem_guidelines",
        "label": "EuSEM — European Society for Emergency Medicine (guidelines urgences)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
        "link_pattern": r"eusem\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|news|join|login)(/|$)",
    },
    # Médecine interne
    {
        "url": "https://efim.org/education/publications",
        "source": "efim_guidelines",
        "label": "EFIM — European Federation Internal Medicine (guidelines médecine interne)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-interne",
        "link_pattern": r"efim\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|jobs|working-groups)(/|$)",
    },
    # Biologie médicale
    {
        "url": "https://www.eflm.eu/site/eflm-publications",
        "source": "eflm_guidelines",
        "label": "EFLM — European Federation Clinical Chemistry (recommendations laboratoire)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "biologiste",
        "link_pattern": r"eflm\.eu/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|jobs|national)(/|$)",
    },
    # Gynécologie / Reproduction
    {
        "url": "https://www.eshre.eu/Guidelines-and-Legal",
        "source": "eshre_guidelines",
        "label": "ESHRE — European Society Human Reproduction (guidelines PMA, gynéco)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
        "link_pattern": r"eshre\.eu/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|news|media|grants|jobs|legal)(/|$)",
    },
    # Ophtalmologie — Glaucome
    {
        "url": "https://eugs.org/guidelines/",
        "source": "egs_guidelines",
        "label": "EGS — European Glaucoma Society (guidelines glaucome 6e éd. 2024)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "link_pattern": r"eugs\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|news|foundation|grants)(/|$)",
    },
    # Ophtalmologie — Rétine
    {
        "url": "https://euretina.org/resource/",
        "source": "euretina_guidelines",
        "label": "EURETINA — European Society of Retina Specialists (guidelines rétine)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "link_pattern": r"euretina\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|news|media|grants|jobs)(/|$)",
    },
    # Dentisterie — Parodontologie
    {
        "url": "https://www.efp.org/education/continuing-education/clinical-guidelines/",
        "source": "efp_guidelines",
        "label": "EFP — European Federation of Periodontology (guidelines parodontologie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "dentiste",
        "link_pattern": r"efp\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|jobs|grants|donate|foundation)(/|$)",
    },
    # Pharmacie hospitalière
    {
        "url": "https://www.eahp.eu/practice-and-policy/statements",
        "source": "eahp_statements",
        "label": "EAHP — European Association Hospital Pharmacists (statements hospitaliers)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pharmacien",
        "link_pattern": r"eahp\.eu/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|news|jobs|grants|awards|press)(/|$)",
    },
]


# =============================================================================
# BACKWARD COMPAT — imports legacy conservés le temps de migrer les appelants
# =============================================================================

ALL_PRATIQUE_FEEDS      = FR_REGULATORY_FEEDS + FR_SOCIETIES_FEEDS
ALL_EUROPE_FEEDS        = EU_FEEDS
ALL_INNOVATION_FEEDS    = JOURNALS_FEEDS
ALL_PRESSE_MEDICALE_FEEDS = CLINICAL_PRESS_FEEDS
EUROPE_WEB_SOURCES_TODO = EU_WEB_SOURCES  # pour web_scraper.py
