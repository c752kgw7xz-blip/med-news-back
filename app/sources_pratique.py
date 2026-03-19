# app/sources_pratique.py
"""
Sources pratiques médicales — recommandations et guides cliniques.

Complète le pipeline réglementaire (JORF, ANSM alertes, HAS alertes) avec des
sources orientées pratique clinique : recommandations de bonne pratique, fiches
mémo, guidelines de sociétés savantes, et bon usage du médicament.

source_type :
  'recommandation' → recommandations HAS, guidelines sociétés savantes, académie
  'therapeutique'  → bon usage médicament, protocoles thérapeutiques
  'formation'      → DPC, accréditation, formations continues

Note : les URLs RSS ont été vérifiées sur les sites officiels.
Certains feeds (sociétés savantes) peuvent nécessiter une vérification
périodique car les sites sont moins stables que les sources institutionnelles.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# HAS — Flux additionnels (compléments à has_rbp déjà existant)
# ---------------------------------------------------------------------------

HAS_FEEDS: list[dict] = [
    # Fiches mémo — synthèses ultra-condensées des recommandations, 1-2 pages,
    # directement actionnables en consultation
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081544",
        "label": "HAS — Fiches mémo",
        "source": "has_fiches_memo",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
    # Parcours de soins — guides d'organisation de la prise en charge par pathologie
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081547",
        "label": "HAS — Parcours de soins",
        "source": "has_parcours",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
]

# ---------------------------------------------------------------------------
# ANSM — Bon usage (positif, complémentaire aux alertes)
# ---------------------------------------------------------------------------

ANSM_BON_USAGE_FEEDS: list[dict] = [
    {
        "url": "https://ansm.sante.fr/rss/bon_usage",
        "label": "ANSM — Bon usage du médicament",
        "source": "ansm_bon_usage",
        "source_type": "therapeutique",
        "audience": ["medecins", "pharmaciens"],
    },
]

# ---------------------------------------------------------------------------
# Académie Nationale de Médecine
# ---------------------------------------------------------------------------

ACADEMIE_FEEDS: list[dict] = [
    {
        "url": "https://www.academie-medecine.fr/feed/",
        "label": "Académie Nationale de Médecine — Publications",
        "source": "academie_medecine",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
]

# ---------------------------------------------------------------------------
# Sociétés savantes par spécialité
# Flux RSS vérifiés — à re-vérifier si une source devient silencieuse
# ---------------------------------------------------------------------------

SOCIETES_SAVANTES_FEEDS: list[dict] = [
    # Cardiologie
    {
        "url": "https://www.sfcardio.fr/rss.xml",
        "label": "Société Française de Cardiologie — Recommandations",
        "source": "sfc_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },
    # Médecine d'urgence
    {
        "url": "https://www.sfmu.org/rss/recommandations.xml",
        "label": "SFMU — Recommandations médecine d'urgence",
        "source": "sfmu_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },
    # Pédiatrie
    {
        "url": "https://www.sfpediatrie.com/feed",
        "label": "Société Française de Pédiatrie",
        "source": "sfp_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },
    # Chirurgie orthopédique
    {
        "url": "https://www.sofcot.fr/rss/publications.xml",
        "label": "SOFCOT — Chirurgie orthopédique et traumatologie",
        "source": "sofcot_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
    },
    # Gynécologie-obstétrique
    {
        "url": "https://www.cngof.fr/feed",
        "label": "CNGOF — Gynécologie-obstétrique",
        "source": "cngof_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
    },
]

# ---------------------------------------------------------------------------
# Export global — tous les feeds pratiques
# ---------------------------------------------------------------------------

ALL_PRATIQUE_FEEDS: list[dict] = (
    HAS_FEEDS
    + ANSM_BON_USAGE_FEEDS
    + ACADEMIE_FEEDS
    + SOCIETES_SAVANTES_FEEDS
)
