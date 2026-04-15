# app/sources_presse_medicale.py
"""
Presse médicale professionnelle — journalistes médicaux, pas chercheurs.

Philosophie :
  Ces sources font déjà le travail de curation editoriale que les journaux
  académiques laissent au lecteur. Un journaliste médical a lu le papier,
  assisté à la session de congrès, interviewé le chirurgien — et écrit
  pour un praticien, pas pour un pair reviewer.

  Conséquence : le filtre LLM doit être très strict (min_score >= 7-8)
  car le volume est élevé et le bruit aussi (brèves, tribunes, politique de santé,
  RH médicales, syndical...). On ne retient que les vraies nouvelles cliniques.

Critère de sélection MedNews pour ces sources :
  "Ce chirurgien vasculaire va-t-il changer quelque chose dans sa pratique
   ou sa planification opératoire s'il lit ça ?"
  → Si non : rejeter sans hésiter.

Sources vérifiées (flux RSS testés — avril 2026) :
  ✅ Vascular Specialist (SVS)  : vascularspecialistonline.com/feed/   ~30-50 items/mois
  ✅ Vascular News              : vascularnews.com/feed/               ~40 items/mois
  ✅ TCTMD                      : tctmd.com/feed                       ~60-80 items/mois
  ✅ Endovascular Today (EVT)   : evtoday.com/rss                      ~100 items/mois
  ✅ Le Quotidien du Médecin    : lequotidiendumedecin.fr/rss.xml
  ✅ Egora                      : egora.fr/rss.xml

  ❌ Cardiovascular News — hors ligne
  ❌ Medscape — 402 (requiert abonnement API)
  ❌ Healio Vascular — pas de RSS identifié

Sources congrès vasculaires (web scraper) :
  ❌ LINC (linc-society.com) — domaine NXDOMAIN ; couvert par TCTMD + Vascular News
  ❌ CIRSE (cirse.org) — JS-rendered, pas de RSS clinique ; couvert par TCTMD
  ❌ ESVS (esvs.org) — RSS admin uniquement ; guidelines via pubmed_ejves
  → Les highlights de congrès sont couverts en temps réel par TCTMD et Vascular News.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Presse spécialisée vasculaire — signal fort, volume modéré
# ---------------------------------------------------------------------------
# Ces deux sources couvrent exclusivement la chirurgie vasculaire et
# endovasculaire. Le bruit existe (portraits, politique des sociétés savantes,
# annonces de congrès sans contenu clinique) mais le ratio est bien meilleur
# que les journaux académiques. min_score=7 : on laisse passer uniquement
# les nouvelles qui ont un impact opérationnel direct.

VASCULAR_PRESS_FEEDS: list[dict] = [

    # ── Vascular Specialist (SVS official newspaper) ──────────────────────
    # Journal officiel de la Society for Vascular Surgery. Couverture :
    # nouveaux dispositifs, résultats d'essais pivots, nouvelles guidelines SVS,
    # comptes-rendus de congrès (VAM, ESVS, VEITH, LINC).
    # Volume : ~30-50 articles/mois. Filtre LLM min_score=7.
    # Exemple de signal fort : "TADV delivers 'transformative advancement'
    # for no-option CLTI" → nouveau dispositif, résultats cliniques.
    {
        "url": "https://vascularspecialistonline.com/feed/",
        "label": "Vascular Specialist (SVS official newspaper)",
        "source": "vascular_specialist",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },

    # ── Vascular News ─────────────────────────────────────────────────────
    # Publication indépendante couvrant chirurgie vasculaire et endovasculaire.
    # Points forts : couverture des congrès ESVS, CIRSE, LINC, ISET ;
    # annonces de dispositifs CE/FDA ; résultats d'études de registre.
    # Volume : ~20-40 articles/mois. Filtre LLM min_score=7.
    # Attention : contient aussi des annonces purement commerciales
    # (acquisitions d'entreprises, nominations) → LLM doit les écarter.
    # Exemple de signal fort : "Reflow Medical — 12-month results DEEPER REVEAL trial"
    {
        "url": "https://vascularnews.com/feed/",
        "label": "Vascular News",
        "source": "vascular_news",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },

    # ── TCTMD (Cardiovascular Research Foundation) ────────────────────────
    # Presse médicale interventionnelle — cardiologie + vasculaire périphérique.
    # Pertinence vasculaire : stenting iliaque, CLTI/AOMI, carotide, accès veineux.
    # NB : couvre aussi la cardiologie interventionnelle (TAVI, coronaire) →
    # le LLM doit écarter tout ce qui ne concerne pas le chirurgien vasculaire.
    # Volume : ~60-80 articles/mois. Filtre LLM min_score=8 (bruit cardio élevé).
    # Couvre les congrès : LINC, CIRSE, TCT, ACC, AHA, PCR — remplace les web scrapers.
    {
        "url": "https://www.tctmd.com/feed",
        "label": "TCTMD — Cardiovascular & Endovascular News",
        "source": "tctmd",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 8,
    },

    # ── Endovascular Today ────────────────────────────────────────────────
    # Publication spécialisée endovasculaire/périphérique vasculaire.
    # Couverture exclusive : AOMI, CLTI, aorte, carotide, veineux, accès vasculaire.
    # Format : résultats d'études, nouveaux dispositifs, revues de techniques.
    # Volume : ~100 articles/mois. RSS vérifié actif (avril 2026).
    # URL: https://www.evtoday.com/rss
    # Bruit faible — min_score=7 (quasi tout est pertinent pour chir vasc).
    {
        "url": "https://www.evtoday.com/rss",
        "label": "Endovascular Today — Peripheral & Endovascular",
        "source": "endovascular_today",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 7,
    },
]

# ---------------------------------------------------------------------------
# Presse médicale française généraliste — bruit élevé, signal rare
# ---------------------------------------------------------------------------
# Ces sources couvrent l'ensemble de la médecine française : politique de santé,
# RH médicales, remboursements, conflits syndicaux, santé publique, et parfois
# une vraie nouvelle clinique. Pour un chirurgien vasculaire, le taux de bruit
# dépasse 95%. min_score=8 : seul un article directement opérationnel passe.
#
# Exemples de REJET systématique :
#   - Grèves, déserts médicaux, gardes de nuit
#   - Remboursements sécu, prix des médicaments génériques
#   - Portraits de médecins, tribunes d'opinion
#   - Campagnes de vaccination grand public
#
# Exemples de signal POSSIBLE (rare) :
#   - Alerte ANSM sur un dispositif vasculaire
#   - Nouvelle indication remboursée pour un traitement vasculaire
#   - Changement de recommandation HAS directement actionnable

FRENCH_MEDICAL_PRESS_FEEDS: list[dict] = [

    # ── Le Quotidien du Médecin ───────────────────────────────────────────
    # Premier quotidien médical français. Lectorat : 100 000+ médecins.
    # Contenu : mélange politique de santé, brèves cliniques, FMC.
    # Pour un chir vasculaire : 1-2 articles pertinents / mois maximum.
    # RSS testé et actif (avril 2026) : https://lequotidiendumedecin.fr/rss.xml
    {
        "url": "https://www.lequotidiendumedecin.fr/rss.xml",
        "label": "Le Quotidien du Médecin",
        "source": "quotidien_medecin",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 8,
    },

    # ── Egora ─────────────────────────────────────────────────────────────
    # Presse médicale pour médecins libéraux. Orientation généraliste/MG.
    # Moins pertinent pour un chirurgien vasculaire hospitalier, mais capture
    # parfois des alertes réglementaires ou des changements de pratique.
    # Volume élevé, bruit maximal → min_score=9 (quasi-intransigeant).
    # RSS testé et actif (avril 2026) : http://www.egora.fr/rss.xml
    {
        "url": "http://www.egora.fr/rss.xml",
        "label": "Egora — Presse médicale libérale",
        "source": "egora",
        "source_type": "innovation",
        "audience": ["medecins"],
        "specialty_hint": "tous",
        "min_score_hint": 9,
    },
]

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

ALL_PRESSE_MEDICALE_FEEDS: list[dict] = (
    VASCULAR_PRESS_FEEDS
    + FRENCH_MEDICAL_PRESS_FEEDS
)
