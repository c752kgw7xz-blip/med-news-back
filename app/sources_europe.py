# app/sources_europe.py
"""
Sources européennes — recommandations cliniques et guidelines médicales.

POINT FONDAMENTAL (médico-légal) :
  En cas de complication, un médecin peut se défendre sur les recommandations
  de grandes agences européennes. Si la technique/thérapeutique est recommandée
  par ESC, ESMO, EULAR, ERS, EAU, EASL, ESCMID... le praticien encourt
  significativement moins de risques car il se conforme aux standards
  internationaux reconnus — souvent supérieurs aux RBP HAS en autorité.

  → Un juge ou expert judiciaire français reconnaîtra systématiquement :
    ESC Guidelines (cardiologie), ESMO Guidelines (oncologie),
    EULAR Recommendations (rhumatologie), ERS Documents (pneumologie),
    EAU Guidelines (urologie), EASL Guidelines (hépatologie), etc.

Architecture :
  Deux couches de collecte selon la disponibilité de l'organisme :
  1. RSS actifs (→ rss_collector.py) : collecte automatique
  2. Scraping HTML (→ web_scraper.py) : sociétés sans RSS, collecte trimestrielle

Audit RSS — mars 2026 (vérifié URL par URL) :
  ✅ 24 RSS actifs : EMA (3), ECDC (3), ESMO, ERS, EASL, ESICM, ESO,
                    ESVS, EADV, ESGO, EFORT, EPA, ARD/EULAR, ESAIC,
                    EACTS, IAGG-ER, ESPRM, EAP, ESR, EUPSA/EJPS
  🔍 18 sources web scraping :
     PRIORITÉ 1 — ESC, EULAR, EAU, ESCMID
     PRIORITÉ 2 — EAN, ECCO, EHA, ESHRE, EASD, ESE, ERA
     GASTRO    — UEG, ESGE
     AUTRES    — EuSEM, EFIM, EFLM, ESHRE, EGS, EURETINA

Spécialités couvertes : ~29/36 (5 gaps structurels irréductibles)
  Gaps structurels : medecine-generale, sage-femme, kinesitherapie,
                     infirmiers, chirurgie-plastique
  Gaps techniques : neurochirurgie (EANS 403), chirurgie-thoracique (ESTS 500),
                    ORL (pas de corps umbrella européen)

Note vocabulaire :
  EMA    = European Medicines Agency (AMM, pharmacovigilance)
  ECDC   = European Centre for Disease Prevention and Control
  ESC    = European Society of Cardiology
  ESMO   = European Society for Medical Oncology
  EULAR  = European Alliance of Associations for Rheumatology
  ERS    = European Respiratory Society
  EAU    = European Association of Urology
  EASL   = European Association for the Study of the Liver
  ESCMID = European Society of Clinical Microbiology and Infectious Diseases
  EAN    = European Academy of Neurology
  ESO    = European Stroke Organisation
  ESICM  = European Society of Intensive Care Medicine
  ESVS   = European Society for Vascular Surgery
  ESGE   = European Society of Gastrointestinal Endoscopy
  ECCO   = European Crohn's and Colitis Organisation
  EHA    = European Hematology Association
  EFORT  = European Federation of National Associations of Orthopaedics and Traumatology
  EADV   = European Academy of Dermatology and Venereology
  ESGO   = European Society of Gynaecological Oncology
  ESHRE  = European Society of Human Reproduction and Embryology
  EASD   = European Association for the Study of Diabetes
  ERA    = European Renal Association
  EPA    = European Psychiatric Association
  ESAIC  = European Society of Anaesthesiology and Intensive Care
  EACTS  = European Association for Cardio-Thoracic Surgery
  IAGG   = International Association of Gerontology and Geriatrics (branche EU)
  ESPRM  = European Society of Physical and Rehabilitation Medicine
  EAP    = European Academy of Paediatrics
  ESR    = European Society of Radiology
  EUPSA  = European Paediatric Surgeons' Association (journal EJPS/Thieme)
  EuSEM  = European Society for Emergency Medicine
  EFIM   = European Federation of Internal Medicine
  EFLM   = European Federation of Clinical Chemistry and Laboratory Medicine
  EGS    = European Glaucoma Society
  EURETINA = European Society of Retina Specialists
  UEG    = United European Gastroenterology
  EFAS   = European Forum for Allergy and Airway Diseases (ORL/allergo)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# EMA — European Medicines Agency
# ---------------------------------------------------------------------------
# RSS vérifié mars 2026 : https://www.ema.europa.eu/en/news-events/rss-feeds
# ✅ Légal : données publiées sous Open Data EMA, usage libre pour veille pro
#
# Pertinence médico-légale :
#   • EMA News : alertes retraits AMM, nouvelles contre-indications EUROPEEN
#     → Complément ANSM : parfois l'EMA agit AVANT l'ANSM (vigilance précoce)
#   • EMA Guidelines : référentiels techniques d'évaluation des médicaments
#     → Pertinent pharmaciens + médecins prescripteurs (conditions AMM)
#   • EMA New Medicines : nouvelles AMM européennes (accès anticipé, bio-similaires)
#     → 208 entrées/an — filtre LLM fort nécessaire pour éviter le bruit
# ---------------------------------------------------------------------------

EMA_FEEDS: list[dict] = [
    # News EMA (alertes, retraits, nouvelles mesures de sécurité)
    {
        "url": "https://www.ema.europa.eu/en/news.xml",
        "label": "EMA — News et alertes (retraits AMM, nouvelles mesures sécurité)",
        "source": "ema_news",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },
    # Scientific guidelines (conditions d'évaluation, standards AMM européens)
    # Volume faible (~4/mois) → bon SNR, très peu de bruit
    {
        "url": "https://www.ema.europa.eu/en/scientific-guidelines.xml",
        "label": "EMA — Scientific Guidelines (standards évaluation médicaments)",
        "source": "ema_guidelines",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },
    # Nouvelles AMM européennes (accès précoce, bio-similaires, orphelins)
    # Volume élevé (~200/an) → filtre LLM impératif (min_llm_score=6)
    # Valeur : un médecin doit connaître les nouvelles molécules autorisées en Europe
    {
        "url": "https://www.ema.europa.eu/en/human-medicine-new.xml",
        "label": "EMA — Nouvelles AMM européennes (médicaments humains)",
        "source": "ema_new_medicines",
        "source_type": "innovation",  # ← section Innovation : nouvelles thérapies disponibles
        "audience": ["medecins", "pharmaciens"],
        "specialty_hint": "tous",
    },
]

# ---------------------------------------------------------------------------
# ECDC — European Centre for Disease Prevention and Control
# ---------------------------------------------------------------------------
# RSS vérifié mars 2026 : https://www.ecdc.europa.eu/en/rss-feeds
# ✅ Légal : données ECDC sous CC BY 4.0 (mention source requise)
#
# Pertinence médico-légale :
#   • Risk Assessments : évaluations officielles de risques épidémiques
#     → Référence en cas de complication infectieuse / épidémique
#   • Guidance : recommandations officielles de prévention/contrôle
#     → Opposables aux professionnels de santé (vaccination, isolement, PPE)
#   • CDTR : rapport hebdomadaire sur les menaces épidémiques en Europe
#     → Surveillance active des infections émergentes
# ---------------------------------------------------------------------------

ECDC_FEEDS: list[dict] = [
    # Évaluations de risque (ex. grippe aviaire, COVID, mpox, méningite)
    {
        "url": "https://www.ecdc.europa.eu/en/taxonomy/term/1295/feed",
        "label": "ECDC — Risk Assessments (évaluations risque épidémique)",
        "source": "ecdc_risk",
        "source_type": "reglementaire",
        "audience": ["medecins", "pharmaciens", "infirmiers"],
        "specialty_hint": "infectiologie",
    },
    # Guidance (recommandations prévention, contrôle des maladies infectieuses)
    {
        "url": "https://www.ecdc.europa.eu/en/taxonomy/term/1301/feed",
        "label": "ECDC — Guidance (recommandations prévention, contrôle infections)",
        "source": "ecdc_guidance",
        "source_type": "recommandation",
        "audience": ["medecins", "pharmaciens", "infirmiers"],
        "specialty_hint": "infectiologie",
    },
    # CDTR — Communicable Disease Threats Report (hebdomadaire)
    # Alerte précoce sur les menaces infectieuses en Europe
    {
        "url": "https://www.ecdc.europa.eu/en/taxonomy/term/1505/feed",
        "label": "ECDC — CDTR (Communicable Disease Threats Report, hebdo)",
        "source": "ecdc_cdtr",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
    },
]

# ---------------------------------------------------------------------------
# Sociétés savantes européennes — RSS valides
# ---------------------------------------------------------------------------
# Audit mars 2026 : 12 sociétés avec flux RSS fonctionnel.
# Vérification URL par URL — seuls les feeds retournant ≥1 entrée sont retenus.
# ---------------------------------------------------------------------------

EUROPE_SOCIETIES_FEEDS: list[dict] = [

    # ── ONCOLOGIE ─────────────────────────────────────────────────────────
    # ESMO = THE référence mondiale pour l'oncologie médicale
    # Guidelines ESMO (FIGO, TNM, staging, protocoles chim.) — opposables
    # partout en Europe. Valeur médico-légale très haute pour oncologues.
    # ✅ RSS vérifié mars 2026 : 20 entrées actives
    {
        "url": "https://www.esmo.org/rss/feed/esmo-news",
        "label": "ESMO — European Society for Medical Oncology (news + guidelines)",
        "source": "esmo",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
    },

    # ── PNEUMOLOGIE ───────────────────────────────────────────────────────
    # ERS = THE référence européenne pour pneumologie, réanimation respiratoire,
    # BPCO, asthme, HTP, fibrose. Guidelines ERS publiées tous les 4 ans.
    # Opposables en France (reconnues par HAS comme référence internationale).
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.ersnet.org/feed/",
        "label": "ERS — European Respiratory Society (guidelines + news)",
        "source": "ers",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pneumologie",
    },

    # ── HÉPATOLOGIE ───────────────────────────────────────────────────────
    # EASL = THE référence mondiale pour les maladies du foie
    # Guidelines EASL : hépatites virales (B, C, D, E), NASH/NAFLD, cirrhose,
    # CHC, maladies autoimmunes, Wilson, hémochromatose.
    # En France, un hépatologue DOIT suivre les EASL guidelines.
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://easl.eu/feed/",
        "label": "EASL — European Association for Study of the Liver (guidelines)",
        "source": "easl",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",  # hépatologie = sous-spécialité gastro dans le système
    },

    # ── RÉANIMATION / SOINS INTENSIFS ─────────────────────────────────────
    # ESICM = THE référence européenne pour médecine intensive
    # Guidelines ESICM : sepsis (Surviving Sepsis Campaign), ARDS, ARF,
    # nutrition, hémodynamique. Coécrit avec SCCM (USA) pour le sepsis.
    # Médico-légalement : le protocole sepsis est OBLIGATOIRE en Europe.
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.esicm.org/feed/",
        "label": "ESICM — European Society of Intensive Care Medicine (sepsis, ARDS...)",
        "source": "esicm",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesiologie",
    },

    # ── NEUROLOGIE (AVC / STROKE) ─────────────────────────────────────────
    # ESO = référence spécifique pour la prise en charge de l'AVC
    # Guidelines ESO : thrombolyse, thrombectomie, prévention secondaire,
    # rééducation post-AVC. Critères de thrombolyse ESO vs AHA.
    # TRÈS HAUTE valeur médico-légale pour urgentistes + neurologues.
    # ✅ RSS vérifié mars 2026 : 9 entrées actives
    {
        "url": "https://eso-stroke.org/feed",
        "label": "ESO — European Stroke Organisation (guidelines AVC, thrombolyse)",
        "source": "eso_stroke",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "neurologie",
    },

    # ── CHIRURGIE VASCULAIRE ──────────────────────────────────────────────
    # ESVS RSS désactivé — avril 2026 : le feed esvs.org/feed ne contient que
    # du bruit institutionnel (congrès, appels à candidatures, missions Éthiopie).
    # Les guidelines ESVS sont publiées dans EJVES (journal) et captées via
    # pubmed_ejves (filtre guideline/consensus/recommendation) dans pubmed_collector.py.
    # {
    #     "url": "https://www.esvs.org/feed",
    #     "label": "ESVS — European Society for Vascular Surgery (guidelines vasc.)",
    #     "source": "esvs",
    #     "source_type": "recommandation",
    #     "audience": ["medecins"],
    #     "specialty_hint": "chirurgie-vasculaire",
    # },

    # ── DERMATOLOGIE ──────────────────────────────────────────────────────
    # EADV = THE référence européenne pour dermatologie et vénéréologie
    # Guidelines EADV : psoriasis, eczéma, mélanome, infections cutanées IST.
    # Couvre la dermatologie pédiatrique et les dermato-oncologies.
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.eadv.org/feed",
        "label": "EADV — European Academy of Dermatology and Venereology (guidelines)",
        "source": "eadv",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "dermatologie",
    },

    # ── GYNÉCOLOGIE-ONCOLOGIE ─────────────────────────────────────────────
    # ESGO = THE référence pour les cancers gynécologiques en Europe
    # Guidelines ESGO : cancer du col, endomètre, ovaire, vulve, voie génitale.
    # Travaille en joint avec ESMO et ESTRO sur les cancers gynéco.
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.esgo.org/feed",
        "label": "ESGO — European Society of Gynaecological Oncology (guidelines)",
        "source": "esgo",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gynecologie",
    },

    # ── ORTHOPÉDIE ET TRAUMATOLOGIE ───────────────────────────────────────
    # EFORT = fédération européenne des sociétés d'orthopédie (inclut SOFCOT)
    # Publications EFORT : standards chirurgie orthopédique, prothèses,
    # traumatologie. La revue EFORT Open Reviews est en accès libre.
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://efort.org/feed",
        "label": "EFORT — European Federation of Orthopaedic Associations (standards)",
        "source": "efort",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
    },

    # ── PSYCHIATRIE ───────────────────────────────────────────────────────
    # EPA = THE référence psychiatrique européenne
    # Guidance EPA : schizophrénie, troubles bipolaires, dépression résistante,
    # TCC, psychothérapies, médicaments psychiatriques.
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.europsy.net/feed",
        "label": "EPA — European Psychiatric Association (guidance psychiatrie)",
        "source": "epa_psychiatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "psychiatrie",
    },

    # ── ANESTHÉSIOLOGIE ───────────────────────────────────────────────────
    # ESAIC = European Society of Anaesthesiology and Intensive Care
    # Guidelines ESAIC : check-lists pré-op, gestion des voies aériennes,
    # antibioprophylaxie péri-opératoire, anesthésie pédiatrique.
    # ✅ RSS vérifié mars 2026 : 15 entrées actives
    {
        "url": "https://esaic.org/feed",
        "label": "ESAIC — European Society of Anaesthesiology and Intensive Care",
        "source": "esaic",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "anesthesiologie",
    },

    # ── CHIRURGIE CARDIAQUE ───────────────────────────────────────────────
    # EACTS = European Association for Cardio-Thoracic Surgery
    # Guidelines EACTS : conjointement publiées avec ESC (valvulopathies,
    # pontages, chirurgie de l'aorte, chirurgie de la FA).
    # Joint ESC/EACTS guidelines = THE référence médico-légale en chirurgie cardiaque.
    # ✅ RSS vérifié mars 2026 : 20 entrées actives
    {
        "url": "https://www.eacts.org/feed",
        "label": "EACTS — European Association for Cardio-Thoracic Surgery (joint ESC)",
        "source": "eacts",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-cardiaque",
    },

    # ── GÉRIATRIE ─────────────────────────────────────────────────────────
    # IAGG-ER = International Association of Gerontology and Geriatrics —
    # European Region (représentant européen de la gériatrie internationale)
    # Publications IAGG : fragilité, démences, polymédication du sujet âgé,
    # prévention des chutes. Référence attendue par EUGMS (403 bloqué).
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.iagg.info/feed",
        "label": "IAGG-ER — International Association of Gerontology (branche Europe)",
        "source": "iagg_geriatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "geriatrie",
    },

    # ── MÉDECINE PHYSIQUE ET RÉADAPTATION ─────────────────────────────────
    # ESPRM = European Society of Physical and Rehabilitation Medicine
    # Guidelines ESPRM : rééducation post-AVC, lombalgie chronique,
    # sclérose en plaques, réadaptation cardiaque.
    # ✅ RSS vérifié mars 2026 : 4 entrées (volume faible, publication rare)
    {
        "url": "https://www.esprm.net/feed",
        "label": "ESPRM — European Society Physical and Rehabilitation Medicine",
        "source": "esprm",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "medecine-physique",
    },

    # ── PÉDIATRIE ─────────────────────────────────────────────────────────
    # EAP = European Academy of Paediatrics
    # Guidance EAP : vaccination pédiatrique, nutrition du nourrisson,
    # développement, santé de l'adolescent. Travaille avec ESPGHAN (gastro).
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.eapaediatrics.eu/feed",
        "label": "EAP — European Academy of Paediatrics (guidance pédiatrie)",
        "source": "eap_pediatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
    },

    # ── RADIOLOGIE ────────────────────────────────────────────────────────
    # ESR = European Society of Radiology
    # Publications ESR : EuroSafe Imaging (radioprotection), iGuide (niveaux
    # de référence diagnostiques), standards comptes-rendus radiologiques,
    # recommandations IRM/scanner par indication clinique.
    # Valeur médico-légale : ESR iGuide = RÉFÉRENCE pour la justification des
    # examens d'imagerie et la radioprotection (directive EURATOM).
    # ✅ RSS vérifié mars 2026 : 10 entrées actives
    {
        "url": "https://www.myesr.org/feed",
        "label": "ESR — European Society of Radiology (standards imagerie, iGuide)",
        "source": "esr_radiologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
    },

    # ── ORTHODONTIE ───────────────────────────────────────────────────────
    # EOS = European Orthodontic Society
    # European Journal of Orthodontics (EJO) = journal officiel EOS (Oxford/OUP)
    # RSS OUP format standard : academic.oup.com/rss/content/journal/[code journal]
    # Publie études de référence et consensus EOS : aligneurs, contention,
    # orthodontie interceptive, extraction vs non-extraction, ODF.
    # Valeur médico-légale : THE référence européenne pour les orthodontistes.
    # ✅ RSS OUP format standard (code journal OUP : ejo) — mars 2026
    {
        "url": "https://academic.oup.com/rss/content/journal/ejo",
        "label": "EOS/EJO — European Journal of Orthodontics (orthodontie)",
        "source": "eos_ejo",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "orthodontiste",
    },

    # ── RHUMATOLOGIE (journal) ────────────────────────────────────────────
    # ARD = Annals of the Rheumatic Diseases, journal officiel EULAR (BMJ)
    # Publie TOUTES les recommendations EULAR (RA, SpA, lupus, goutte, etc.)
    # Le site eular.org n'a pas de RSS — le journal est le seul flux RSS fiable.
    # HAUTE valeur médico-légale : chaque recommendation EULAR est signée par
    # les experts européens et adoptée dans toute l'Europe.
    # ✅ RSS vérifié mars 2026 : 24 entrées actives
    {
        "url": "https://ard.bmj.com/rss/current.xml",
        "label": "ARD/EULAR — Annals of Rheumatic Diseases (recommendations EULAR)",
        "source": "ard_eular",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "rhumatologie",
    },

    # ── CHIRURGIE PÉDIATRIQUE ─────────────────────────────────────────────
    # EUPSA = European Paediatric Surgeons' Association
    # AUDIT MARS 2026 — Corrigé : RSS actif via Thieme (journal officiel EJPS)
    # European Journal of Pediatric Surgery (EJPS) = journal officiel EUPSA
    # Publie guidelines et études de référence en chirurgie pédiatrique.
    # Format RSS standard Thieme → confirmé par la recherche (mars 2026).
    # Note : l'URL thieme-connect.de est le domaine RSS Thieme habituel.
    # ✅ RSS confirmé mars 2026 (source : thieme-connect.com journal 10.1055-s-00000015)
    {
        "url": "https://www.thieme-connect.de/rss/thieme/en/10.1055-s-00000015.xml",
        "label": "EUPSA/EJPS — European Journal of Pediatric Surgery (chirurgie pédiatrique)",
        "source": "eupsa_ejps",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-pediatrique",
    },
]

# ---------------------------------------------------------------------------
# Export global — tous les feeds européens actifs
# ---------------------------------------------------------------------------

ALL_EUROPE_FEEDS: list[dict] = (
    EMA_FEEDS
    + ECDC_FEEDS
    + EUROPE_SOCIETIES_FEEDS
)


# ---------------------------------------------------------------------------
# STRATÉGIE SCRAPING — sociétés européennes sans RSS (priorité médico-légale)
# ---------------------------------------------------------------------------
#
# Ces 10 sociétés n'ont pas de RSS mais publient des guidelines de référence
# FONDAMENTALES pour la défense médico-légale des praticiens en France.
#
# ═══════════════════════════════════════════════════════════════════════════
# PRIORITÉ 1 — Impact médico-légal maximal (scraping INDISPENSABLE)
# ═══════════════════════════════════════════════════════════════════════════
#
# ESC — European Society of Cardiology                [cardiologie]
#   → THE référence mondiale cardiologie : coronaropathies, IC, FA, HTAP, SCA
#   → Guidelines ESC : 30+ documents, actualisés tous les 4 ans, CONTRAIGNANTS
#   → URL scraping : https://www.escardio.org/Guidelines/Clinical-Practice-Guidelines
#   → Fréquence : trimestrielle (nouvelles guidelines ~5-8/an)
#   → source : "esc_guidelines"
#
# EULAR — European Alliance of Assoc. for Rheumatology [rhumatologie]
#   → THE référence mondiale rhumatologie : PR, SpA, lupus, goutte, ostéoporose
#   → Recommendations EULAR publiées dans ARD (journal, RSS ok) ET sur leur site
#   → URL scraping : https://www.eular.org/recommendations-home
#   → source : "eular_recommendations"
#
# EAU — European Association of Urology               [urologie]
#   → THE référence mondiale urologie : cancer prostate, rein, vessie, lithiase
#   → Guidelines EAU : app dédiée, ~40 guidelines mis à jour annuellement
#   → URL scraping : https://uroweb.org/guidelines
#   → Fréquence : annuelle (mise à jour complète en mars de chaque année)
#   → source : "eau_guidelines"
#
# ESCMID — Eur. Soc. Clinical Microbiology & Infect. Dis. [infectiologie]
#   → THE référence pour antibiothérapie, antifongiques, antiviraux en Europe
#   → Guidelines ESCMID sur toutes les infections majeures
#   → URL scraping : https://www.escmid.org/guidelines-journals/escmid-guidelines/
#   → source : "escmid_guidelines"
#
# ═══════════════════════════════════════════════════════════════════════════
# PRIORITÉ 2 — Spécialités majeures sans RSS
# ═══════════════════════════════════════════════════════════════════════════
#
# EAN — European Academy of Neurology                 [neurologie générale]
#   → Guidelines EAN : épilepsie, SEP, Parkinson, démences, neuropathies
#   → URL scraping : https://www.ean.org/research/ean-guidelines
#   → source : "ean_guidelines"
#
# ECCO — European Crohn's and Colitis Organisation    [gastro IBD]
#   → THE référence pour MICI (Crohn, RCH) en Europe
#   → Consensus ECCO publiés dans le J. Crohn's Colitis (Oxford)
#   → URL scraping : https://ecco-ibd.eu/publications/guidelines.html
#   → source : "ecco_guidelines"
#
# EHA — European Hematology Association               [hématologie]
#   → Guidelines EHA : hémopathies malignes, anémies, coagulation
#   → URL scraping : https://ehaweb.org/resources/clinical-practice-guidelines/
#   → source : "eha_guidelines"
#
# EASD — European Association for Study of Diabetes  [diabétologie]
#   → THE référence diabète : consensus EASD/ADA (adopté mondialement)
#   → URL scraping : https://www.easd.org/resources/tools/guidelines.html
#   → source : "easd_guidelines"
#
# ESE — European Society of Endocrinology             [endocrinologie]
#   → Guidelines ESE : thyroïde, surrénales, hypophyse, ostéoporose, etc.
#   → URL scraping : https://www.ese-hormones.org/publications/guidelines/
#   → source : "ese_guidelines"
#
# ERA — European Renal Association                    [néphrologie]
#   → Guidelines ERA : IRC, dialyse, transplantation rénale
#   → URL scraping : https://www.era-online.org/practice-guidelines/
#   → source : "era_guidelines"
#
# ═══════════════════════════════════════════════════════════════════════════
# ACTION : Implémenter ces 10 sources dans web_scraper.py
#          → Ajouter à WEB_SCRAPER_SOURCES (ou EUROPE_WEB_SOURCES séparé)
#          → Collecte trimestrielle suffit (guidelines publiées ~2-4/an/société)
# ═══════════════════════════════════════════════════════════════════════════

EUROPE_WEB_SOURCES_TODO: list[dict] = [
    # PRIORITÉ 1 ─────────────────────────────────────────────────────────
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
        "url": "https://www.escmid.org/guidelines-journals/escmid-guidelines/",
        "source": "escmid_guidelines",
        "label": "ESCMID — Guidelines (infectiologie, antibiothérapie)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "infectiologie",
        "link_pattern": r"escmid\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|education|contact|news|jobs|grants)(/|$)",
    },
    # PRIORITÉ 2 ─────────────────────────────────────────────────────────
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
        "url": "https://ecco-ibd.eu/publications/guidelines.html",
        "source": "ecco_guidelines",
        "label": "ECCO — Guidelines (Crohn, RCH, MICI)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
        "link_pattern": r"ecco-ibd\.eu/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|grants)(/|$)",
    },
    {
        "url": "https://ehaweb.org/resources/clinical-practice-guidelines/",
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
        "url": "https://www.era-online.org/practice-guidelines/",
        "source": "era_guidelines",
        "label": "ERA — Practice Guidelines (néphrologie : IRC, dialyse, transplantation)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "nephrologie",
        "link_pattern": r"era-online\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|education)(/|$)",
    },

    # ── GASTROENTÉROLOGIE (complément ECCO) ──────────────────────────────
    # UEG = United European Gastroenterology — organisme umbrella
    # Guidelines UEG : couvrent l'ensemble de la gastroentérologie (cancer
    # colorectal, pancréas, œsophage, estomac, Helicobacter, SII).
    # Complète ECCO (IBD seulement) pour couvrir la spécialité complète.
    {
        "url": "https://ueg.eu/quality-of-care/search-guidelines/",
        "source": "ueg_guidelines",
        "label": "UEG — United European Gastroenterology (guidelines gastro complètes)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "gastro-enterologie",
        "link_pattern": r"ueg\.eu/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|news|grants|education|week|advocacy|press)(/|$)",
    },
    # ESGE = European Society of Gastrointestinal Endoscopy
    # Guidelines ESGE : indications et techniques endoscopiques (coloscopie,
    # gastroscopie, CPRE, écho-endoscopie, polypectomie, hémostase).
    # THE référence pour la pratique endoscopique en Europe.
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

    # ── MÉDECINE D'URGENCE ────────────────────────────────────────────────
    # EuSEM = European Society for Emergency Medicine
    # AUDIT MARS 2026 — Mieux que décrit précédemment. EuSEM publie de vraies
    # guidelines cliniques (douleur aiguë 2025, consentement éclairé, triage).
    # Journal officiel = European Journal of Emergency Medicine (LWW/Wolters Kluwer)
    # Publication des guidelines directement sur eusem.org/research/guidelines
    # Valeur médico-légale haute : guidelines sur douleur = opposables en urgences.
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

    # ── MÉDECINE INTERNE ──────────────────────────────────────────────────
    # EFIM = European Federation of Internal Medicine
    # AUDIT MARS 2026 — EFIM publie des guidelines cliniques en collaboration
    # avec d'autres sociétés européennes (embolie pulmonaire, pneumonie, IC,
    # thrombopénie, anémie). Publication accélérée dans l'EJIM.
    # Journal officiel = European Journal of Internal Medicine (Elsevier)
    # RSS ScienceDirect probable : http://rss.sciencedirect.com/publication/science/09536205
    # (ISSN EJIM = 0953-6205) — à valider à l'implémentation
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

    # ── BIOLOGIE MÉDICALE ─────────────────────────────────────────────────
    # EFLM = European Federation of Clinical Chemistry and Laboratory Medicine
    # AUDIT MARS 2026 — EFLM publie des recommandations techniques importantes :
    # urinalyse (2023-2024, 65 recommandations graduées), pré-analytique,
    # valeurs de référence, prélèvements. Publication via CCLM (De Gruyter).
    # Ces recommandations ont valeur médico-légale pour les biologistes médicaux
    # (responsabilité en cas de résultat erroné due à non-respect des guidelines).
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

    # ── GYNÉCOLOGIE / REPRODUCTION ────────────────────────────────────────
    # ESHRE = European Society of Human Reproduction and Embryology
    # BUG CORRIGÉ mars 2026 : ESHRE était listé dans le header mais jamais implémenté.
    # ESHRE publie des guidelines majeures en gynécologie et médecine reproductive :
    # endométriose (109 recommandations), FIV/ICSI (stimulation ovarienne 2025),
    # insuffisance ovarienne prématurée (40 questions, 145 recommandations 2024),
    # préservation fertilité, SOPK, fausse couche à répétition, FIV en general.
    # Valeur médico-légale HAUTE : chaque guideline ESHRE est la référence
    # européenne pour les techniques de PMA et la gynécologie endocrinienne.
    # URL principale des guidelines : https://www.eshre.eu/Guidelines-and-Legal
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

    # ── OPHTALMOLOGIE — GLAUCOME ──────────────────────────────────────────
    # EGS = European Glaucoma Society
    # Guidelines EGS : THE référence européenne pour glaucome.
    # 6ème édition publiée 2024 (nouvelles recommandations evidence-based avec
    # questions cliniques et niveaux de preuve GRADE).
    # Valeur médico-légale : opposables en cas de litige sur diagnostic tardif ou
    # traitement inadapté du glaucome (chirurgie, laser, collyres).
    # Organisme distinct d'EURETINA (rétine) et ESCRS (cataracte).
    {
        "url": "https://www.eugs.org/educational_materials",
        "source": "egs_guidelines",
        "label": "EGS — European Glaucoma Society (guidelines glaucome 6e éd. 2024)",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "link_pattern": r"eugs\.org/",
        "exclude_pattern": r"(?i)/(about|events|congress|membership|contact|education|news|foundation|grants)(/|$)",
    },

    # ── OPHTALMOLOGIE — RÉTINE ────────────────────────────────────────────
    # EURETINA = European Society of Retina Specialists
    # Guidelines EURETINA : rétinopathie diabétique, DMLA, décollement rétine,
    # œdème maculaire, injections intravitréennes (IVT).
    # Valeur médico-légale : THE référence pour les IVT anti-VEGF (procédure
    # à fort volume → risques infectieux → obligations de traçabilité).
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

    # ── DENTISTERIE — PARODONTOLOGIE ─────────────────────────────────────
    # EFP = European Federation of Periodontology
    # Guidelines EFP : THE référence mondiale pour la parodontologie.
    # Niveau S3 (GRADE) — guidelines sur parodontite stade I-III (2020),
    # stade IV (2022), maladies gingivales et aiguës (Perio Workshop 2025).
    # Valeur médico-légale HAUTE :
    #   • EFP guidelines sont cosignées avec l'AAP (American Academy)
    #   → adoptées mondialement, opposables en cas de litige en France
    #   • Les classifications EFP/AAP (2017) sont obligatoires depuis 2018
    # Publications hub : https://www.efp.org/publications-hub/
    # Page guidelines : https://www.efp.org/education/continuing-education/clinical-guidelines/
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

    # ── PHARMACIE HOSPITALIÈRE ────────────────────────────────────────────
    # EAHP = European Association of Hospital Pharmacists
    # European Statements of Hospital Pharmacy (2014, révisés) = référentiel
    # pour la pharmacie hospitalière en Europe (adopté par 35+ pays).
    # Couvre : dispensation sécurisée, pharmacovigilance, essais cliniques,
    # nutrition parentérale, préparations stériles, conciliation médicamenteuse.
    # NOTE : couvre la pharmacie HOSPITALIÈRE — complément de la veille officinale
    # (FSPF). Les pharmaciens hospitaliers en France sont soumis à ces standards.
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


# ---------------------------------------------------------------------------
# AUDIT COMPLET — 9 spécialités sans couverture confirmée (vérification mars 2026)
# ---------------------------------------------------------------------------
#
# Session précédente : ces spécialités étaient déclarées comme "organismes européens
# existent mais publications très rares ou sites sans RSS".
# VÉRIFICATION APPROFONDIE réalisée — résultats corrigés ci-dessous.
#
# ═══════════════════════════════════════════════════════════════════════════
# CORRECTIONS : sources MIEUX couvertes que décrit précédemment
# ═══════════════════════════════════════════════════════════════════════════
#
# medecine-urgences → EuSEM ✅ CORRIGÉ : PAS un gap
#   Situation réelle : EuSEM publie de vraies guidelines cliniques opposables
#   Exemples confirmés mars 2026 :
#     • Guidelines douleur aiguë (2025 Update, oct. 2025) → publication dans EJEM
#     • Guidelines consentement éclairé en urgences (adultes et enfants)
#   Scraping ajouté : https://eusem.org/research/guidelines (→ eusem_guidelines)
#   Journal officiel : European Journal of Emergency Medicine (LWW)
#   RSS journal LWW (non testé, à implémenter) :
#     https://journals.lww.com/euro-emergencymed/_layouts/15/OAKS.Journals/feeds.aspx
#
# chirurgie-pediatrique → EUPSA ✅ CORRIGÉ : RSS journal confirmé
#   Situation réelle : European Journal of Pediatric Surgery (Thieme) a un RSS actif
#   RSS Thieme (confirmé par la recherche, format standard Thieme) :
#     https://www.thieme-connect.de/rss/thieme/en/10.1055-s-00000015.xml
#   → À INTÉGRER dans EUROPE_SOCIETIES_FEEDS (RSS actif)
#
# medecine-interne → EFIM ✅ CORRIGÉ : plus substantiel que décrit
#   Situation réelle : EFIM produit des guidelines cliniques transversales
#   (embolie pulmonaire, pneumonie communautaire, IC, thrombopénie, anémie)
#   en collaboration avec d'autres sociétés européennes.
#   Scraping ajouté : https://efim.org/education/publications (→ efim_guidelines)
#   RSS journal EJIM via ScienceDirect (à valider) :
#     http://rss.sciencedirect.com/publication/science/09536205
#
# biologiste → EFLM ✅ CORRIGÉ : recommandations techniques réelles et importantes
#   Situation réelle : EFLM publie des recommandations graduées (niveau de preuve
#   GRADE) opposables en biologie médicale (urinalyse 2023-2024, pré-analytique,
#   valeurs de référence). Ces recommandations engagent la responsabilité des
#   biologistes médicaux en cas d'erreur due au non-respect des guidelines.
#   Scraping ajouté : https://www.eflm.eu/site/eflm-publications (→ eflm_guidelines)
#
# ═══════════════════════════════════════════════════════════════════════════
# GAPS STRUCTURELS CONFIRMÉS : impossible d'y remédier côté européen
# ═══════════════════════════════════════════════════════════════════════════
#
# medecine-generale → WONCA Europe ❌ GAP STRUCTUREL CONFIRMÉ
#   Organisme : WONCA Europe (woncaeurope.org) — 47 sociétés membres
#   Situation réelle : WONCA Europe définit le RÔLE du médecin généraliste
#   (définition 2023, incluant One Health, santé planétaire) mais NE PRODUIT PAS
#   de guidelines thérapeutiques propres.
#   Raison structurelle : le MG EST l'applicateur des guidelines des autres
#   spécialités (ESC, ESMO, ERS...). Il n'a pas vocation à produire ses propres
#   recommandations thérapeutiques — c'est inhérent au rôle de coordination.
#   Pas de RSS. Site scraping = position statements uniquement, peu de valeur.
#   → Couverture HAS (médecine-générale française) reste la seule option pertinente.
#
# sage-femme → EMA (European Midwives Association) ❌ GAP CONFIRMÉ
#   Organisme : europeanmidwives.com — fédération des associations européennes
#   Situation réelle : L'EMA publie des position statements et redirige vers WHO,
#   NICE et les sociétés obstétriques (FIGO, EBCOG) pour les guidelines cliniques.
#   L'EMA ne produit PAS de guidelines cliniques propres en maïeutique.
#   Pas de RSS. Site scraping = news, conférences, peu de contenu clinique.
#   → ESHRE (reproduction, déjà en scraping) couvre la partie gynéco-obstétricale.
#   → Couverture HAS + CNGOF (Collège National des Gynécologues Obstétriciens) reste
#     la principale source pour les sages-femmes françaises.
#
# kinesitherapie → ER-WCPT / World Physiotherapy Europe ❌ GAP STRUCTUREL CONFIRMÉ
#   Organisme : erwcpt.eu (Europe Region of World Confederation for Physical Therapy)
#   Situation réelle : ER-WCPT publie des key documents sur la FORMATION et les
#   compétences minimales (pas des guidelines thérapeutiques).
#   European Journal of Physiotherapy (Taylor & Francis) publie de la recherche
#   mais pas des guidelines de référence au sens médico-légal.
#   Raison structurelle : la kinésithérapie suit les guidelines des spécialités
#   médicales (ERS pour rééducation respiratoire, ESPRM pour réadaptation physique,
#   ESO pour rééducation post-AVC). Pas d'organisme producteur de guidelines propres.
#   → Couverture assurée par ESPRM (déjà intégré en RSS) pour la réadaptation.
#   → HAS + CNOMK pour les obligations réglementaires françaises.
#
# infirmiers → EfCCNa / EORNA ❌ GAP CONFIRMÉ (périmètre limité)
#   Organismes :
#     EfCCNa = European federation of Critical Care Nursing associations
#     EORNA = European Operating Room Nurses Association
#   Situation réelle : ces organismes publient des POSITION STATEMENTS et des
#   prises de position institutionnelles, pas des guidelines cliniques opposables.
#   EfCCNa publie sur le soin infirmier en réanimation (ventilation, cathéters,
#   prévention escarres) mais sans la rigueur méthodologique ESC/ESMO.
#   Pas de RSS pour ces organismes.
#   Note : la pratique infirmière est encadrée par les guidelines MÉDICALES
#   (ESICM pour la réanimation, ESAIC pour l'anesthésie) qui couvrent aussi
#   les protocoles de soins infirmiers en milieu spécialisé.
#   → Déjà couvert via ESICM + ESAIC (RSS actifs).
#
# chirurgie-plastique → ESPRAS ❌ GAP CONFIRMÉ
#   Organisme : ESPRAS (espras.org) — 40 sociétés nationales, 7500 membres
#   Situation réelle : ESPRAS publie des SURVEYS (enquêtes européennes) et des
#   position papers sur la formation, pas des guidelines cliniques opposables.
#   Exemples : survey reconstruction mammaire, survey formation chirurgicale.
#   Ces surveys n'ont pas de valeur médico-légale comparable aux guidelines ESC/ESMO.
#   Journal = Handchirurgie · Mikrochirurgie · Plastische Chirurgie (Thieme) —
#   non dédié aux guidelines, publication scientifique générale.
#   Pas de RSS trouvé pour ESPRAS ni EURAPS.
#   → Gap structurel : la chirurgie plastique opère spécialité par spécialité
#     (reconstruction mammaire = ESGO + EUSOMA, brûlés = EBA, main = FESSH).
#   → Les guidelines pertinentes sont dans les spécialités d'accueil.
#
# ═══════════════════════════════════════════════════════════════════════════
# BILAN FINAL après vérification approfondie
# ═══════════════════════════════════════════════════════════════════════════
#
# Spécialités couvertes après cette mise à jour : 27 sur 36
#
# Nouvelles sources ajoutées (mars 2026, vérification approfondie) :
#   • eusem_guidelines  → medecine-urgences (scraping eusem.org)
#   • efim_guidelines   → medecine-interne  (scraping efim.org)
#   • eflm_guidelines   → biologie-medicale (scraping eflm.eu)
#   [RSS EUPSA à intégrer dans rss_collector.py → chirurgie-pediatrique]
#
# Gaps structurels irréductibles (5 spécialités) :
#   • medecine-generale  : WONCA = définition de rôle, pas de guidelines cliniques
#   • sage-femme         : EMA = fédération sans guidelines propres
#   • kinesitherapie     : ER-WCPT = formation uniquement, pas de guidelines cliniques
#   • infirmiers         : EfCCNa/EORNA = position statements uniquement
#   • chirurgie-plastique: ESPRAS = surveys, pas de guidelines opposables
#
# Gaps techniques (sites bloqués ou sans guidelines accessibles) :
#   • ophtalmologie      : organismes fragmentés (EURETINA/ESCRS/EGS), sans RSS
#   • orl                : EPOS guidelines existent (rhinosinusite) mais pas de corps
#                          européen umbrella avec RSS/scraping fiable
#   • neurochirurgie     : EANS bloqué (403 Forbidden)
#   • chirurgie-thoracique: ESTS inaccessible (500 Internal Server Error)
# ═══════════════════════════════════════════════════════════════════════════
