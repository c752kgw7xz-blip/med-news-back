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

État des sources (mars 2026) — scanné via check_societes_savantes_rss.py + validation manuelle :
  ✅ 34 sociétés savantes avec flux RSS valide
  ❌ SFMG, Cardio-online, SRLF, SFD-dermato, SFO, SPILF, SFR, SFH — pas de RSS
  ❌ SFRO — sfro.org ≠ SFRO française ; sfro.fr = site congrès sans RSS utile
  ❌ ansm_bon_usage, sfc, sfp, sofcot — confirmés sans RSS
  ❌ sfa-allergologie.org — site non fonctionnel

Note : les feeds de sociétés savantes contiennent aussi des annonces de congrès
et actualités professionnelles. Le filtre LLM (min_llm_score=4) écarte le bruit.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# HAS — Flux additionnels (compléments à has_rbp déjà existant)
# ---------------------------------------------------------------------------

HAS_FEEDS: list[dict] = [
    # Fiches mémo — synthèses ultra-condensées, directement actionnables
    # Publications peu fréquentes (mensuel à trimestriel)
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081544",
        "label": "HAS — Fiches mémo",
        "source": "has_fiches_memo",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
    # Parcours de soins — guides d'organisation par pathologie
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081547",
        "label": "HAS — Parcours de soins",
        "source": "has_parcours",
        "source_type": "recommandation",
        "audience": ["medecins"],
    },
    # Commission de la Transparence — décisions de remboursement (ASMR/SMR)
    # Impact direct : médicaments remboursables, nouvelles inscriptions, radiations
    # ⚠ À VALIDER : l'ID RSS de la CT HAS — vérifier sur
    #   https://www.has-sante.fr/jcms/c_1771214/fr/nos-flux-d-information-rss
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081459",
        "label": "HAS — Commission de la Transparence (avis médicaments)",
        "source": "has_ct",
        "source_type": "therapeutique",
        "audience": ["medecins", "pharmaciens"],
    },
]

# ---------------------------------------------------------------------------
# INCa — Institut National du Cancer
# ---------------------------------------------------------------------------

INCA_FEEDS: list[dict] = [
    # Référentiels et recommandations oncologie — LA référence nationale cancer
    # ⚠ À VALIDER : URL RSS e-cancer.fr — vérifier sur https://www.e-cancer.fr
    {
        "url": "https://www.e-cancer.fr/Actualites-et-evenements/Actualites/rss",
        "label": "INCa — Actualités et référentiels oncologie",
        "source": "inca",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },
]

# ---------------------------------------------------------------------------
# ANDPC — Agence Nationale du DPC (Formation continue obligatoire)
# ---------------------------------------------------------------------------

ANDPC_FEEDS: list[dict] = [
    # Informations DPC : nouvelles obligations, accréditations, changements réglementaires
    # NB : le catalogue de formations lui-même n'est pas un RSS utile —
    #      on vise ici les actualités/modifications du cadre DPC
    # ⚠ À VALIDER : URL RSS andpc.fr — vérifier sur https://www.andpc.fr
    {
        "url": "https://www.andpc.fr/rss",
        "label": "ANDPC — Actualités DPC et formation continue",
        "source": "andpc",
        "source_type": "formation",
        "audience": ["medecins"],
    },
]

# ---------------------------------------------------------------------------
# Académie Nationale de Médecine ✅
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
# Sociétés savantes — 15 sources avec RSS valide (scan mars 2026)
# ---------------------------------------------------------------------------

SOCIETES_SAVANTES_FEEDS: list[dict] = [

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
        "url": "https://www.sfhta.eu/feed",
        "label": "SFHTA — Société Française d'Hypertension Artérielle",
        "source": "sfhta",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "cardiologie",
    },

    # ── Anesthésie-Réanimation ────────────────────────────────────────────
    {
        "url": "https://sfar.org/feed",
        "label": "SFAR — Société Française d'Anesthésie et de Réanimation",
        "source": "sfar",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesie-reanimation",
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
    {
        "url": "https://www.sfpsy.org/feed",
        "label": "SFP — Société Française de Psychiatrie",
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
        "specialty_hint": "gastroenterologie",
    },

    # ── Hépatologie ───────────────────────────────────────────────────────
    {
        "url": "https://afef.asso.fr/feed",
        "label": "AFEF — Association Française pour l'Étude du Foie",
        "source": "afef",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "hepatologie",
    },

    # ── Pneumologie ───────────────────────────────────────────────────────
    {
        "url": "https://splf.fr/feed",
        "label": "SPLF — Société de Pneumologie de Langue Française",
        "source": "splf",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
    },

    # ── Endocrinologie ────────────────────────────────────────────────────
    {
        "url": "https://www.sfendocrino.org/feed",
        "label": "SFE — Société Française d'Endocrinologie",
        "source": "sfendocrino",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
    },

    # ── Diabétologie ──────────────────────────────────────────────────────
    {
        "url": "https://www.sfdiabete.org/rss.xml",
        "label": "SFD — Société Francophone du Diabète",
        "source": "sfdiabete",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "endocrinologie",
    },

    # ── Rhumatologie ──────────────────────────────────────────────────────
    {
        "url": "https://www.larhumatologie.fr/feed",
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
        "url": "https://www.urofrance.org/feed",
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
    # Feed valide, publications peu fréquentes → lancer avec days=365
    {
        "url": "https://www.cngof.fr/feed",
        "label": "CNGOF — Collège National des Gynécologues et Obstétriciens Français",
        "source": "cngof_recommandations",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
    },

    # ── Néphrologie ───────────────────────────────────────────────────────
    {
        "url": "https://www.sfndt.org/actualites/feed",
        "label": "SFNDT — Société Francophone de Néphrologie Dialyse et Transplantation",
        "source": "sfndt",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "nephrologie",
    },

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
        "specialty_hint": "gastroenterologie",
    },

    # ── Microbiologie ─────────────────────────────────────────────────────
    {
        "url": "https://www.sfm-microbiologie.org/feed/",
        "label": "SFM — Société Française de Microbiologie",
        "source": "sfm_microbiologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
    },

    # ── Chirurgie vasculaire ──────────────────────────────────────────────
    {
        "url": "https://www.vasculaire.com/feed/",
        "label": "SCVE/SFCV — Société de Chirurgie Vasculaire et Endovasculaire",
        "source": "sfcv",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
    },

    # ── Proctologie ───────────────────────────────────────────────────────
    {
        "url": "https://sofcpre.fr/feed/",
        "label": "SOFCPRE — Société Française et Francophone de Chirurgie de l'Obésité et des Maladies Métaboliques",
        "source": "sofcpre",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastroenterologie",
    },

    # ── Médecine physique et réadaptation ─────────────────────────────────
    {
        "url": "https://www.sofmer.com/feed/",
        "label": "SOFMER — Société Française de Médecine Physique et de Réadaptation",
        "source": "sofmer",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-physique",
    },

    # ── Médecine vasculaire ───────────────────────────────────────────────
    {
        "url": "https://sfmv.fr/feed/",
        "label": "SFMV — Société Française de Médecine Vasculaire",
        "source": "sfmv",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
    },

    # ── Médecine du sport ─────────────────────────────────────────────────
    {
        "url": "https://www.sfms.fr/feed/",
        "label": "SFMS — Société Française de Médecine du Sport",
        "source": "sfms",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-generale",
    },

    # ── Alcoologie ────────────────────────────────────────────────────────
    {
        "url": "https://sfalcoologie.fr/feed/",
        "label": "SFA — Société Française d'Alcoologie",
        "source": "sfalcoologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-interne",
    },

    # ── Anatomie pathologique ─────────────────────────────────────────────
    {
        "url": "https://www.sfpathol.org/feed/",
        "label": "SFP — Société Française de Pathologie",
        "source": "sfpathol",
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

    # ── Stomatologie / Chirurgie maxillo-faciale ──────────────────────────
    {
        "url": "https://www.sfscmfco.com/feed/",
        "label": "SFSCMFCO — Société Française de Stomatologie, Chirurgie Maxillo-Faciale et Chirurgie Orale",
        "source": "sfscmfco",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "orl",
    },

    # ── Médecine d'urgence ────────────────────────────────────────────────
    {
        "url": "https://www.sfmu.org/feed/",
        "label": "SFMU — Société Française de Médecine d'Urgence",
        "source": "sfmu",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },

    # ── Pédiatrie ─────────────────────────────────────────────────────────
    {
        "url": "https://www.sfpediatrie.com/feed/",
        "label": "SFP — Société Française de Pédiatrie",
        "source": "sfpediatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # ── Néonatalogie ──────────────────────────────────────────────────────
    {
        "url": "https://www.societe-francaise-neonatalogie.com/feed/",
        "label": "SFN — Société Française de Néonatalogie",
        "source": "sfnn",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # ── Santé publique ────────────────────────────────────────────────────
    {
        "url": "https://www.sfsp.fr/feed/",
        "label": "SFSP — Société Française de Santé Publique",
        "source": "sfsp",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-generale",
    },

    # ── Dermatologie ──────────────────────────────────────────────────────
    {
        "url": "https://www.sfdermato.org/feed/",
        "label": "SFDermato — Société Française de Dermatologie",
        "source": "sfdermato",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
    },

    # ── Ophtalmologie ─────────────────────────────────────────────────────
    {
        "url": "https://www.sfo-online.fr/feed/",
        "label": "SFO — Société Française d'Ophtalmologie",
        "source": "sfo",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
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

    # ── Hématologie ───────────────────────────────────────────────────────
    {
        "url": "https://sfh.hematologie.net/feed/",
        "label": "SFH — Société Française d'Hématologie",
        "source": "sfh",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
    },

    # ── Radiologie diagnostique ───────────────────────────────────────────
    {
        "url": "https://www.radiologie.fr/feed/",
        "label": "SFR — Société Française de Radiologie",
        "source": "sfr_radiologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
    },

    # ── Chirurgie orthopédique ────────────────────────────────────────────
    {
        "url": "https://www.sofcot.fr/feed/",
        "label": "SOFCOT — Société Française de Chirurgie Orthopédique et Traumatologique",
        "source": "sofcot",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
    },

    # ── Chirurgie plastique ───────────────────────────────────────────────
    {
        "url": "https://www.sofcpre.fr/feed/",
        "label": "SOFCPRE — Société Française de Chirurgie Plastique Reconstructrice et Esthétique",
        "source": "sofcpre_plastique",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-plastique",
    },

    # ── Chirurgie pédiatrique ─────────────────────────────────────────────
    {
        "url": "https://www.chirurgie-pediatrique.com/feed/",
        "label": "SFCP — Société Française de Chirurgie Pédiatrique",
        "source": "sfcp",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-pediatrique",
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

    # ── Kinésithérapie ────────────────────────────────────────────────────
    {
        "url": "https://www.ffmkr.org/feed/",
        "label": "FFMKR — Fédération Française des Masseurs Kinésithérapeutes Rééducateurs",
        "source": "ffmkr",
        "source_type": "recommandation",
        "audience": ["paramedical"],
        "specialty_hint": "kinesitherapie",
    },

    # ── Sage-femme ────────────────────────────────────────────────────────
    {
        "url": "https://www.college-sages-femmes.fr/feed/",
        "label": "CNSF — Collège National des Sages-Femmes de France",
        "source": "cnsf",
        "source_type": "recommandation",
        "audience": ["paramedical"],
        "specialty_hint": "sage-femme",
    },

    # ── Biologie médicale ─────────────────────────────────────────────────
    {
        "url": "https://www.sfbc-asso.fr/feed/",
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

# ---------------------------------------------------------------------------
# Export global — tous les feeds pratiques actifs
# ---------------------------------------------------------------------------

ALL_PRATIQUE_FEEDS: list[dict] = (
    HAS_FEEDS
    + ACADEMIE_FEEDS
    + INCA_FEEDS
    + ANDPC_FEEDS
    + SOCIETES_SAVANTES_FEEDS
)
