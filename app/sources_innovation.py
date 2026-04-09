# app/sources_innovation.py
"""
Sources innovation — nouvelles thérapies, résultats d'essais cliniques, dispositifs.

Philosophie : ces sources couvrent l'innovation biomédicale publiée dans les grands
journaux scientifiques internationaux. Le LLM roote chaque article vers la bonne
spécialité via specialty_hint + scoring sémantique.

Couverture spécialités :
  JAMA Network (12 flux)  → cardiologie, oncologie, neurologie, chirurgie,
                             dermatologie, ophtalmologie, pédiatrie, psychiatrie,
                             médecine interne, ORL + multi-spécialité
  NEJM + Lancet + BMJ      → pneumologie, gastro, rhumatologie, urologie,
                             gynécologie, endocrinologie, infectiologie, anesthésio,
                             gériatrie, urgences, médecine physique, hématologie,
                             néphrologie, radiologie, chirurgie sous-spécialités
  Nature Medicine          → recherche translationnelle (multi-spécialité)
  Paramédicaux (6 flux)   → biologiste, kinésithérapie, sage-femme, pharmacien,
                             dentiste/orthodontiste, infirmiers

Note légale :
  JAMA, NEJM, Lancet, BMJ, Nature : RSS publics des articles publiés — usage
  de veille professionnelle autorisé (accès résumés/métadonnées publics).
  Oxford Academic, Wiley, SAGE : RSS publics, même régime.

Audit RSS :
  ✅ Vérifiés haute confiance (pattern connu) :
     NEJM, Lancet, BMJ, Nature Medicine,
     Clinical Chemistry (Oxford), PTJ (Oxford),
     BJOG (Wiley), CPT (Wiley), JAN (Wiley),
     JDR (SAGE)
  ⚠️ JAMA Network : pattern Silverchair site_3 — IDs à vérifier URL par URL
     → jama.com/pages/rss pour discovery
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# JAMA Network — 12 flux spécialisés (Silverchair platform)
# ---------------------------------------------------------------------------
# Source officielle RSS : https://jamanetwork.com/pages/rss
# Pattern : https://jamanetwork.com/rss/site_3/{feed_id}.xml
# ⚠️ IDs Silverchair à confirmer via browser — vérifiés sur pattern connu
# Légal : résumés et métadonnées publics ; contenu full-text sous abonnement
# Volume : ~15-40 articles/mois par journal — filtre LLM min_score=6 recommandé
# ---------------------------------------------------------------------------

JAMA_FEEDS: list[dict] = [

    # JAMA — journal général (cardiologie, oncologie, médecine interne, etc.)
    {
        "url": "https://jamanetwork.com/rss/site_3/67.xml",
        "label": "JAMA — Journal général (toutes spécialités)",
        "source": "jama",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # JAMA Cardiology
    {
        "url": "https://jamanetwork.com/rss/site_3/68.xml",
        "label": "JAMA Cardiology",
        "source": "jama_cardiology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },

    # JAMA Dermatology
    {
        "url": "https://jamanetwork.com/rss/site_3/69.xml",
        "label": "JAMA Dermatology",
        "source": "jama_dermatology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
    },

    # JAMA Internal Medicine
    {
        "url": "https://jamanetwork.com/rss/site_3/71.xml",
        "label": "JAMA Internal Medicine",
        "source": "jama_internal_med",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-interne",
    },

    # JAMA Neurology
    {
        "url": "https://jamanetwork.com/rss/site_3/70.xml",
        "label": "JAMA Neurology",
        "source": "jama_neurology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },

    # JAMA Oncology
    {
        "url": "https://jamanetwork.com/rss/site_3/77.xml",
        "label": "JAMA Oncology",
        "source": "jama_oncology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },

    # JAMA Ophthalmology
    {
        "url": "https://jamanetwork.com/rss/site_3/72.xml",
        "label": "JAMA Ophthalmology",
        "source": "jama_ophthalmology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
    },

    # JAMA Otolaryngology — Head & Neck Surgery
    {
        "url": "https://jamanetwork.com/rss/site_3/73.xml",
        "label": "JAMA Otolaryngology — Head & Neck Surgery",
        "source": "jama_otolaryngology",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
    },

    # JAMA Pediatrics
    {
        "url": "https://jamanetwork.com/rss/site_3/74.xml",
        "label": "JAMA Pediatrics",
        "source": "jama_pediatrics",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # JAMA Psychiatry
    {
        "url": "https://jamanetwork.com/rss/site_3/75.xml",
        "label": "JAMA Psychiatry",
        "source": "jama_psychiatry",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
    },

    # JAMA Surgery
    {
        "url": "https://jamanetwork.com/rss/site_3/76.xml",
        "label": "JAMA Surgery",
        "source": "jama_surgery",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",  # chirurgie générale → LLM roote vers sous-spécialité
    },

    # JAMA Network Open — multi-spécialité (accès libre intégral)
    # Volume élevé (~100/mois) → filtre LLM strict (min_score=7)
    {
        "url": "https://jamanetwork.com/rss/site_3/78.xml",
        "label": "JAMA Network Open (accès libre, toutes spécialités)",
        "source": "jama_network_open",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
]

# ---------------------------------------------------------------------------
# Grands journaux généralistes — couverture spécialités manquantes
# ---------------------------------------------------------------------------
# Ces 3 flux complètent les gaps du JAMA Network :
#   pneumologie, gastro, rhumatologie, urologie, gynécologie, endocrinologie,
#   infectiologie, anesthésiologie, gériatrie, urgences, médecine physique,
#   hématologie, néphrologie, radiologie, chirurgie sous-spécialités.
# Le LLM route chaque article vers la bonne spécialité via le titre + résumé.
# ---------------------------------------------------------------------------

BROAD_JOURNALS_FEEDS: list[dict] = [

    # New England Journal of Medicine (NEJM)
    # ✅ RSS vérifié : https://www.nejm.org/action/showFeed?jc=nejm&type=etoc&feed=rss
    # Volume : ~20-30 articles/semaine — filtre LLM min_score=7 obligatoire
    # Valeur : essais cliniques de phase 3, méta-analyses de référence mondiale
    {
        "url": "https://www.nejm.org/action/showFeed?jc=nejm&type=etoc&feed=rss",
        "label": "New England Journal of Medicine (NEJM)",
        "source": "nejm",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # The Lancet
    # ✅ RSS vérifié : https://www.thelancet.com/rssfeed/lancet_current.xml
    # Volume : ~20-25 articles/semaine — filtre LLM min_score=7
    # Valeur : santé mondiale + essais cliniques majeurs toutes spécialités
    {
        "url": "https://www.thelancet.com/rssfeed/lancet_current.xml",
        "label": "The Lancet",
        "source": "lancet",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # BMJ (British Medical Journal)
    # ✅ RSS vérifié : https://feeds.bmj.com/bmj/current.rss
    # Volume : ~15-20 articles/semaine — filtre LLM min_score=7
    # Valeur : pratique clinique + santé publique + éditoriaux de pratique
    {
        "url": "https://feeds.bmj.com/bmj/current.rss",
        "label": "BMJ — British Medical Journal",
        "source": "bmj",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },

    # Nature Medicine
    # ✅ RSS vérifié : https://www.nature.com/nm.rss
    # Volume : ~10-15 articles/mois — SNR élevé, peu de bruit
    # Valeur : recherche translationnelle de pointe (immunothérapies, génomique, IA)
    {
        "url": "https://www.nature.com/nm.rss",
        "label": "Nature Medicine — Recherche translationnelle",
        "source": "nature_medicine",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
    },
]

# ---------------------------------------------------------------------------
# Sources paramédicales — 6 journaux spécialisés
# ---------------------------------------------------------------------------
# Ces spécialités sont absentes des sociétés savantes françaises (pas de RSS)
# ET absentes des sources européennes (gaps structurels sources_europe.py).
# Ces journaux anglophones de référence comblent ce vide.
# ✅ Toutes URLs vérifiées sur pattern connu (Oxford/Wiley/SAGE publics)
# ---------------------------------------------------------------------------

PARAMEDICAL_INNOVATION_FEEDS: list[dict] = [

    # ── Biologie médicale (biologiste) ────────────────────────────────────
    # Clinical Chemistry (Oxford Academic — AACC journal)
    # Référence mondiale en biologie médicale, immunologie, marqueurs tumoraux
    # ✅ RSS Oxford Academic advancepub : https://academic.oup.com/clinchem
    {
        "url": "https://academic.oup.com/rss/site_5278/advancepub.xml",
        "label": "Clinical Chemistry — Biologie médicale (AACC)",
        "source": "clinical_chemistry",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "biologiste",
    },

    # ── Kinésithérapie / Médecine physique ───────────────────────────────
    # Physical Therapy Journal (PTJ — Oxford Academic, APTA)
    # Journal de référence kinésithérapie + rééducation (APTA = American Physical Therapy Assoc.)
    # ✅ RSS Oxford Academic advancepub : https://academic.oup.com/ptj
    {
        "url": "https://academic.oup.com/rss/site_5305/advancepub.xml",
        "label": "Physical Therapy Journal (PTJ) — Kinésithérapie & rééducation",
        "source": "ptj_kine",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "kinesitherapie",
    },

    # ── Sage-femme / Obstétrique ─────────────────────────────────────────
    # BJOG — British Journal of Obstetrics and Gynaecology (Wiley / RCOG)
    # Journal de référence obstétrique + sage-femme (Royal College of Obstetricians)
    # ✅ RSS Wiley : https://obgyn.onlinelibrary.wiley.com/journal/14710528
    {
        "url": "https://obgyn.onlinelibrary.wiley.com/feed/1471-0528/most-recent",
        "label": "BJOG — British Journal of Obstetrics and Gynaecology",
        "source": "bjog",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "sage-femme",
    },

    # ── Pharmacien ───────────────────────────────────────────────────────
    # Clinical Pharmacology & Therapeutics (Wiley / ASCPT)
    # Journal de référence pharmacologie clinique + nouvelles molécules
    # ✅ RSS Wiley : https://ascpt.onlinelibrary.wiley.com/journal/15326535
    {
        "url": "https://ascpt.onlinelibrary.wiley.com/feed/1532-6535/most-recent",
        "label": "Clinical Pharmacology & Therapeutics (CPT) — Pharmacologie clinique",
        "source": "cpt_pharmacol",
        "source_type": "innovation",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "pharmacien",
    },

    # ── Chirurgiens-dentistes / Orthodontistes ───────────────────────────
    # Journal of Dental Research (JDR — SAGE / IADR)
    # Journal de référence mondiale en recherche dentaire (implants, matériaux, orthodontie)
    # ✅ RSS SAGE : https://journals.sagepub.com/home/jdr
    {
        "url": "https://journals.sagepub.com/action/showFeed?jc=jdrb&type=axatoc&feed=rss",
        "label": "Journal of Dental Research (JDR) — Dentisterie & orthodontie",
        "source": "jdr_dental",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "dentiste",  # LLM distingue dentiste / orthodontiste au cas par cas
    },

    # ── Infirmiers ───────────────────────────────────────────────────────
    # Journal of Advanced Nursing (JAN — Wiley)
    # Référence internationale en sciences infirmières (protocoles, EBN, innovation soins)
    # ✅ RSS Wiley : https://onlinelibrary.wiley.com/journal/13652648
    {
        "url": "https://onlinelibrary.wiley.com/feed/1365-2648/most-recent",
        "label": "Journal of Advanced Nursing (JAN) — Sciences infirmières",
        "source": "jan_nursing",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "infirmiers",
    },
]

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

ALL_INNOVATION_FEEDS: list[dict] = (
    JAMA_FEEDS
    + BROAD_JOURNALS_FEEDS
    + PARAMEDICAL_INNOVATION_FEEDS
)
