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

Audit RSS complet — mars 2026 (vérifié URL par URL via browser) :
  ✅ 34 sources avec flux RSS valide (voir SOCIETES_SAVANTES_FEEDS)
  ✅ SFMU : URL corrigée → https://www.sfmu.org/full-rss.php

  ❌ has_fiches_memo (p_3081544) — ID HAS invalide ; contenu inclus dans has_rbp
  ❌ has_parcours (p_3081547)    — ID HAS invalide ; contenu inclus dans has_rbp

  ❌ Sans RSS — specialties sans alternative connue (suivi manuel recommandé) :
     SFH  (hématologie)        sfh.hematologie.net    — aucun flux, pas de lien RSS
     SFR  (radiologie)         radiologie.fr          — aucun flux RSS détecté
     SFO  (ophtalmologie)      sfo-online.fr/feed/    — 404
     SFCV (chir. vasculaire)   vasculaire.com/feed/   — 404
     SOFCPRE (chir. obésité)   sofcpre.fr/feed/       — 404
     SOFMER (méd. physique)    sofmer.com/feed/       — 404
     SFMV (méd. vasculaire)    sfmv.fr/feed/          — 404
     SFPathol (anatomopathol.) sfpathol.org/feed/     — 404 (site custom)
     SFSCMFCO (stomato/maxillo) sfscmfco.com/feed/    — 404
     SFPédiatrie               sfpediatrie.com/feed/  — 404
     SFNN (néonatalogie)       sfnn.com/feed/         — 404
     SFSP (santé publique)     sfsp.fr/feed/          — 404
     SFCP (chir. pédiatrique)  chirurgie-pediatrique.com/feed/ — 404
     FFMKR (kinésithérapie)    ffmkr.org/feed/        — 404 (OUPS!)
     CNSF (sage-femme)         college-sages-femmes.fr/feed/ — 404
     SOFCOT (orthopédie)       sofcot.fr              — aucun RSS (vérifié sep. 2026)
     SFDermato                 sfdermato.org          — aucun RSS (vérifié sep. 2026)

  → Pour les spécialités sans RSS : voir STRATEGY_NO_RSS en bas de fichier.

Note : les feeds de sociétés savantes contiennent aussi des annonces de congrès
et actualités professionnelles. Le filtre LLM (min_llm_score=4) écarte le bruit.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# HAS — Flux additionnels (compléments à has_rbp déjà existant)
# ---------------------------------------------------------------------------

HAS_FEEDS: list[dict] = [
    # Commission de la Transparence — décisions de remboursement (ASMR/SMR)
    # RSS vérifié mars 2026 : ID p_3081449, feed "HAS - Avis sur les médicaments"
    # Contenu confirmé : KISUNLA (donanémab), ZEMCELPRO, etc.
    # ~500-800 avis/an — haute valeur prescripteurs + pharmaciens
    # Légal : Licence Ouverte Etalab ✅
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081449",
        "label": "HAS — Commission de la Transparence (avis médicaments)",
        "source": "has_ct",
        "source_type": "therapeutique",
        "audience": ["medecins", "pharmaciens"],
    },
    # ❌ Fiches mémo (p_3081544) et Parcours de soins (p_3081547) :
    #    IDs invalides → retournent <root>Invalid parameter</root>
    #    Ces types de contenu sont inclus dans has_rbp (p_3081452, flux principal RBP)
]

# ---------------------------------------------------------------------------
# Sources exclues après audit mars 2026
# ---------------------------------------------------------------------------
# INCa (cancer.fr) :
#   ❌ Aucun RSS sur le site (cancer.fr ni e-cancer.fr)
#   ❌ CGU : réutilisation requiert autorisation préalable
#      → Contacter : servicejuridique@institutcancer.fr pour accord data
#
# ANDPC (agencedpc.fr) :
#   ❌ Aucun RSS (404 sur /rss.xml et /feed)
#   ❌ CGU : "reproduction numérique non autorisée" (L.335-2 CPI)
#   ❌ Volume très faible (~3 articles/trimestre)
#
# Ces listes sont volontairement vides pour garder la trace de la décision.
INCA_FEEDS: list[dict] = []
ANDPC_FEEDS: list[dict] = []

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

    # ❌ SFCV (vasculaire.com/feed/) — 404 mars 2026
    # ❌ SOFCPRE (sofcpre.fr/feed/) — 404 mars 2026
    # ❌ SOFMER (sofmer.com/feed/) — 404 mars 2026
    # ❌ SFMV (sfmv.fr/feed/) — 404 mars 2026

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

    # ❌ SFPathol (sfpathol.org/feed/) — 404 mars 2026 (page custom "introuvable")

    # ── Médecine nucléaire ────────────────────────────────────────────────
    {
        "url": "https://www.cnp-mn.fr/feed/",
        "label": "SFMN — Société Française de Médecine Nucléaire",
        "source": "sfmn",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
    },

    # ❌ SFSCMFCO (sfscmfco.com/feed/) — 404 mars 2026

    # ── Médecine d'urgence ────────────────────────────────────────────────
    # URL corrigée mars 2026 : /feed/ renvoyait vers /fr/feed/ (erreur)
    # URL valide découverte via page flux-rss du site
    {
        "url": "https://www.sfmu.org/full-rss.php",
        "label": "SFMU — Société Française de Médecine d'Urgence",
        "source": "sfmu",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-urgences",
    },

    # ❌ SFPédiatrie (sfpediatrie.com/feed/) — 404 mars 2026
    # ❌ SFNN néonatalogie (sfnn/feed/) — 404 mars 2026
    # ❌ SFSP santé publique (sfsp.fr/feed/) — 404 mars 2026

    # ── Dermatologie ──────────────────────────────────────────────────────
    # ❌ SFDermato (sfdermato.org) : aucun flux RSS disponible (vérifié mars 2026)
    #    /feed, /rss, /rss.xml tous en 404 — pas de balise RSS dans le HTML
    #    → Suivi manuel : https://www.sfdermato.org

    # ── Ophtalmologie ─────────────────────────────────────────────────────
    # ❌ SFO (sfo-online.fr/feed/) — 404 mars 2026

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
    # ❌ SFH (sfh.hematologie.net/feed/) — 404 mars 2026, aucun RSS sur homepage

    # ── Radiologie diagnostique ───────────────────────────────────────────
    # ❌ SFR (radiologie.fr/feed/) — 404 mars 2026, aucun RSS sur radiologie.fr

    # ── Chirurgie orthopédique ────────────────────────────────────────────
    # ❌ SOFCOT (sofcot.fr) : aucun flux RSS disponible (vérifié mars 2026)
    #    /feed et 15+ patterns testés — pas de balise RSS dans le HTML
    #    → Suivi manuel : https://www.sofcot.fr/actualites

    # ❌ SOFCPRE plastique (sofcpre.fr/feed/) — 404 mars 2026
    # ❌ SFCP chirurgie pédiatrique (chirurgie-pediatrique.com/feed/) — 404 mars 2026

    # ── Infirmiers ────────────────────────────────────────────────────────
    {
        "url": "https://www.sniil.fr/feed/",
        "label": "SNIIL — Syndicat National des Infirmières et Infirmiers Libéraux",
        "source": "sniil",
        "source_type": "recommandation",
        "audience": ["paramedical"],
        "specialty_hint": "infirmiers",
    },

    # ❌ FFMKR kinésithérapie (ffmkr.org/feed/) — 404 mars 2026
    # ❌ CNSF sage-femme (college-sages-femmes.fr/feed/) — 404 mars 2026

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


# ---------------------------------------------------------------------------
# STRATEGY_NO_RSS — plan d'action pour les spécialités sans flux RSS
# ---------------------------------------------------------------------------
#
# 15 spécialités importantes n'ont pas de RSS fonctionnel (mars 2026).
# Elles ne peuvent pas être ignorées. Voici les options par priorité :
#
# OPTION A — Surveillance de page web (HTML scraping ciblé)
#   Implémenter un collecteur HTTP qui scrape la page "actualités/publications"
#   de chaque société, extrait les nouveaux liens et les insère comme candidats.
#   Avantages : couvre toutes les sociétés, pas de dépendance RSS
#   Effort : ~2j dev pour un scraper générique + config par société
#   Candidats prioritaires (haute valeur clinique) :
#     • SFH  hématologie     → sfh.hematologie.net/nos-publications
#     • SFR  radiologie      → radiologie.fr/actualites
#     • SFO  ophtalmologie   → sfo-online.fr/recommandations
#     • SFPédiatrie          → sfpediatrie.com/recommandations
#     • SOFCOT orthopédie    → sofcot.fr/actualites
#
# OPTION B — Contact direct des sociétés savantes
#   Demander l'activation d'un flux RSS ou l'accès à une API/newsletter.
#   La plupart des sites sont sous WordPress ou Drupal → RSS natif désactivé.
#   Délai : variable (semaines à mois)
#   Action : envoyer un email type à chaque société (template disponible)
#
# OPTION C — Agrégateurs tiers existants
#   Plusieurs flux agrégés couvrent la littérature médicale française :
#   • SFMU propose déjà un agrégateur pour ses adhérents (revues + sites urgences)
#   • Certaines spécialités publient leurs RBP via la HAS (has_rbp les couvre déjà)
#   • Vidal Reco : https://www.vidal.fr (payant, API possible)
#
# OPTION D — Import manuel trimestriel
#   Pour les spécialités à faible volume (<10 publications/an) :
#   SOFCOT, SFSCMFCO, SFNN, SFCP → vérification manuelle tous les 3 mois
#   via l'interface admin /admin/sources/import
#
# RECOMMANDATION IMMÉDIATE :
#   Implémenter OPTION A pour SFH, SFR, SFO, SFPédiatrie (4 spécialités critiques)
#   → Fichier à créer : app/web_scraper.py avec un collecteur générique
#   → Configurer dans une nouvelle liste WEB_SCRAPER_SOURCES
