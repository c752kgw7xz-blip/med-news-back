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

État des sources (mars 2026) :
  ✅ has_rbp          → flux actif (dans rss_collector.py)
  ✅ has_fiches_memo  → flux actif, publications peu fréquentes (mensuel/trimestriel)
  ✅ has_parcours     → flux actif, publications peu fréquentes
  ✅ academie_medecine → flux actif, 6 articles/90j
  ✅ cngof_recommandations → flux actif, publications > 90j (lancer avec days=365)
  ❌ ansm_bon_usage   → URL RSS inexistante sur ansm.sante.fr
  ❌ sfc_recommandations  → sfcardio.fr n'expose pas de flux RSS
  ❌ sfmu_recommandations → sfmu.org n'expose pas de flux RSS propre
  ❌ sfp_recommandations  → sfpediatrie.com n'expose pas de flux RSS
  ❌ sofcot_recommandations → sofcot.fr n'expose pas de flux RSS

Sources à investiguer pour une prochaine itération :
  - cardio-online.fr (bras média SFC) — tester RSS
  - revmed.ch (Revue Médicale Suisse, FR) — https://www.revmed.ch/rss
  - DPC Connect / ANDPC → pas de RSS public
  - EM-consulte agrégateur → accès payant
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# HAS — Flux additionnels (compléments à has_rbp déjà existant)
# ---------------------------------------------------------------------------

HAS_FEEDS: list[dict] = [
    # Fiches mémo — synthèses ultra-condensées des recommandations, 1-2 pages,
    # directement actionnables en consultation.
    # Publications peu fréquentes (mensuel à trimestriel).
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081544",
        "label": "HAS — Fiches mémo",
        "source": "has_fiches_memo",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
    # Parcours de soins — guides d'organisation de la prise en charge par pathologie.
    # Publications peu fréquentes.
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081547",
        "label": "HAS — Parcours de soins",
        "source": "has_parcours",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
]

# ---------------------------------------------------------------------------
# Académie Nationale de Médecine — actif ✅
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
# Sociétés savantes — seul CNGOF expose un flux RSS valide
# ---------------------------------------------------------------------------

SOCIETES_SAVANTES_FEEDS: list[dict] = [
    # Gynécologie-obstétrique — flux valide, publications peu fréquentes.
    # Lancer collect_pratique avec days=365 pour capturer l'historique.
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
# Export global — tous les feeds pratiques actifs
# ---------------------------------------------------------------------------

ALL_PRATIQUE_FEEDS: list[dict] = (
    HAS_FEEDS
    + ACADEMIE_FEEDS
    + SOCIETES_SAVANTES_FEEDS
)
