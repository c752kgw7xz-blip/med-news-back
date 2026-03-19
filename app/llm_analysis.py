# app/llm_analysis.py
"""
Moteur d'analyse LLM pour les candidats réglementaires.

Pour chaque candidat au statut NEW :
  1. Appel Claude pour scoring + classification
  2. Écriture dans items (review_status = PENDING)
  3. Mise à jour status candidate : LLM_DONE ou LLM_FAILED

Audiences gérées :
  TRANSVERSAL_LIBERAL  : tous les médecins libéraux
  SPECIALITE           : spécialité(s) précise(s)
  PHARMACIENS          : impact spécifique officines / dispensation

Schéma JSON de sortie :
{
  "pertinent": true | false,
  "audience": "TRANSVERSAL_LIBERAL" | "SPECIALITE" | "PHARMACIENS",
  "specialites": ["medecine-generale", "cardiologie", "chirurgie"],
  "type_praticien": "prescripteur" | "interventionnel" | "biologiste" | "pharmacien" | "tous",
  "score_density": 1..10,
  "tri_json": {
    "titre_court":     str,   // ≤ 12 mots
    "resume":          str,   // 2-3 phrases, ce que ça change concrètement
    "impact_pratique": str,   // 1 phrase : action à faire / point à retenir
    "nature":          str,   // ARRETE | DECRET | LOI | ORDONNANCE | RECOMMANDATION | ALERTE | AUTRE
    "date_publication": "YYYY-MM-DD"
  },
  // categorie : clinique | medicament | dispositifs_medicaux | facturation | administratif | sante_publique | exercice
  "lecture_json": {
    "points_cles":  [str, ...],  // 3-5 bullets
    "texte_long":   str,         // analyse complète ~150 mots
    "references":   [str, ...]   // NOR, références légales, numéro AMM…
  }
}
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import re
import time
from typing import Any

import anthropic
import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM backend config — Claude Haiku (async, 20 concurrent)
# ---------------------------------------------------------------------------
ANTHROPIC_MODEL      = "claude-haiku-4-5-20251001"
ANTHROPIC_MAX_TOKENS = 1200

LLM_MODEL = ANTHROPIC_MODEL

_anthropic_client: anthropic.AsyncAnthropic | None = None


def _get_anthropic_client() -> anthropic.AsyncAnthropic:
    global _anthropic_client
    if _anthropic_client is None:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY manquante dans l'environnement")
        _anthropic_client = anthropic.AsyncAnthropic(api_key=key)
    return _anthropic_client

KNOWN_TYPE_PRATICIEN = {"prescripteur", "interventionnel", "biologiste", "pharmacien", "tous"}

KNOWN_SPECIALTIES = {
    # Médecine générale
    "medecine-generale",
    # Spécialités médicales
    "cardiologie", "dermatologie", "endocrinologie", "gastro-enterologie",
    "gynecologie", "neurologie", "ophtalmologie", "orl", "pediatrie",
    "pneumologie", "psychiatrie", "rhumatologie", "urologie",
    "medecine-interne", "medecine-urgences", "geriatrie", "medecine-physique",
    "oncologie", "hematologie", "infectiologie", "nephrologie",
    "radiologie", "anesthesiologie",
    # Chirurgie (sous-spécialités uniquement — "chirurgie" générique interdit)
    "chirurgie-vasculaire", "chirurgie-orthopedique",
    "chirurgie-thoracique", "chirurgie-plastique", "neurochirurgie",
    "chirurgie-pediatrique", "chirurgie-cardiaque",
    # Paramédicaux
    "infirmiers", "kinesitherapie", "sage-femme", "biologiste",
}
KNOWN_AUDIENCES   = {"TRANSVERSAL_LIBERAL", "SPECIALITE", "PHARMACIENS"}

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
Tu es un expert juridique et médical spécialisé dans la veille réglementaire \
pour les professionnels de santé libéraux en France.

On te soumet un texte provenant d'une source officielle : Journal Officiel (JORF), \
convention médicale UNCAM (KALI), recommandation HAS, alerte de sécurité ANSM, \
circulaire ministérielle ou bulletin officiel santé.

Ta mission :

1. PERTINENCE — Ce texte change-t-il quelque chose de concret pour un professionnel \
de santé ? Réponds NON si c'est : une nomination, un avis de concours, \
un texte purement administratif ou budgétaire sans impact sur la pratique ou \
la rémunération, un rapport épidémiologique sans recommandation opérationnelle.

2. AUDIENCE — Qui est principalement concerné ?
   - TRANSVERSAL_LIBERAL : tous les médecins libéraux (facturation, CPAM, \
     CMU, téléconsultation, exercice libéral en général)
   - SPECIALITE : une ou plusieurs spécialités ou professions précises (voir liste ci-dessous)
   - PHARMACIENS : impact DIRECT et EXCLUSIF sur l'exercice en officine. \
     Critères stricts — LE TEXTE DOIT porter sur au moins l'un de ces points : \
     règle de substitution générique, gestion de rupture de stock en officine, \
     obligation légale propre à l'officine (préparations magistrales, \
     dispensation à l'unité, PDA), rémunération ou convention pharmacien, \
     autorisation d'ouverture/fermeture d'officine.

   RÈGLE ANTI-PHARMACIENS — Ces cas NE SONT PAS PHARMACIENS :
   - Retrait AMM ou alerte sécurité médicament → audience = SPECIALITE \
     (médecin prescripteur) ; le pharmacien n'est qu'un relais d'information
   - Nouvelle indication, restriction de prescription, REMS → SPECIALITE
   - Alerte pharmacovigilance sans action officine spécifique → SPECIALITE
   - Tout texte dont l'acteur principal est le médecin prescripteur, \
     même si un médicament est mentionné

   Exemples corrects audience :
     Arrêté substitution biosimilaire en officine  → PHARMACIENS ✓
     Rupture stock amoxicilline (consigne officine) → PHARMACIENS ✓
     Retrait AMM Valsartan (alerte prescripteurs)   → SPECIALITE (cardiologie + medecine-generale) ✓
     Alerte ANSM paracétamol 1g surdosage          → SPECIALITE (medecine-urgences + medecine-generale) ✓
     Nouvelle indication immunothérapie oncologie   → SPECIALITE (oncologie) ✓

RÈGLE D'ATTRIBUTION — À LIRE ATTENTIVEMENT :
1. Commence TOUJOURS par chercher une spécialité précise.
   Demande-toi : "Quel médecin va concrètement changer sa pratique grâce à cet article ?"
2. Si tu identifies une ou plusieurs spécialités concernées
   → utilise SPECIALITE avec les slugs exacts.
   Un article peut avoir 2-4 spécialités simultanément.
3. TRANSVERSAL_LIBERAL uniquement si l'article concerne TOUS les médecins libéraux sans \
   exception possible :
   - Réforme de la convention médicale nationale
   - Modification du tiers payant généralisé
   - Changement du cadre d'exercice libéral général
   - Obligations administratives communes à tous
4. TRANSVERSAL_LIBERAL est INTERDIT pour :
   - Une alerte médicament → spécialité prescriptrice
   - Une recommandation clinique → spécialité concernée
   - Un texte sur une pathologie précise → spécialité
   - Un texte qui mentionne des spécialistes nommément
5. En cas de doute entre TRANSVERSAL et une spécialité → choisis la spécialité.
   Mieux vaut sur-attribuer que sous-attribuer.
Exemples corrects :
  Alerte acide tranexamique → anesthesiologie + chirurgie-orthopedique + medecine-urgences
  Recommandation HAS HTA   → cardiologie + medecine-generale
  Arrêté honoraires        → TRANSVERSAL_LIBERAL ✓
  Modification CCAM        → TRANSVERSAL_LIBERAL ✓

3. SPÉCIALITÉS — Si audience = SPECIALITE, liste les slugs concernés parmi :

   Médecine générale : medecine-generale

   Spécialités médicales : cardiologie, dermatologie, endocrinologie, \
gastro-enterologie, gynecologie, neurologie, ophtalmologie, orl, pediatrie, \
pneumologie, psychiatrie, rhumatologie, urologie, medecine-interne, \
medecine-urgences, geriatrie, medecine-physique, oncologie, hematologie, \
infectiologie, nephrologie, radiologie, anesthesiologie

   Chirurgie — TOUJOURS choisir la sous-spécialité exacte (le slug "chirurgie" \
générique n'existe pas) : chirurgie-vasculaire, chirurgie-orthopedique, \
chirurgie-thoracique, chirurgie-plastique, neurochirurgie, \
chirurgie-pediatrique, chirurgie-cardiaque

   Paramédicaux : infirmiers, kinesitherapie, sage-femme, biologiste

   Règles :
   - Distingue la sous-spécialité chirurgicale exacte plutôt que "chirurgie" générique.
   - Pour les paramédicaux, utilise leurs slugs dédiés (infirmiers, kinesitherapie, \
sage-femme, biologiste) plutôt que TRANSVERSAL_LIBERAL.
   - Un texte peut concerner plusieurs spécialités : retourne un tableau complet.

4. SCORE D'URGENCE (score_density) de 1 à 10 :
   - 1-3 : informatif, pas d'action immédiate
   - 4-6 : à lire, impact modéré sur la pratique
   - 7-10 : lecture OBLIGATOIRE — change la pratique, la rémunération, \
     ou crée une obligation légale immédiate

   Exemples de score 9-10 : avenant tarifaire UNCAM, retrait AMM médicament courant, \
   nouvelle obligation de formation, modification majeure de la convention médicale.
   Exemples de score 1-2 : recommandation de bonnes pratiques informatifs, \
   rapport sans modification réglementaire.

5. RÉDACTION — Résumé clair et direct pour un professionnel pressé. \
   Pas de jargon juridique, phrases courtes, impact concret en premier.

6. CATÉGORIE MÉTIER — Assigne UNE seule valeur parmi :
   - clinique              : recommandations HAS, protocoles, guidelines diagnostiques ou thérapeutiques
   - medicament            : alertes pharmacovigilance sur une MOLÉCULE nommée, retrait/suspension AMM, \
nouvelle indication thérapeutique, modification posologie/CI/contre-indication, \
remboursement d'un médicament — STRICTEMENT pharmacologie et prescription médicamenteuse
   - dispositifs_medicaux  : alertes matériovigilance, problèmes de sécurité ou réglementation \
concernant équipements médicaux, imagerie (IRM, scanner, échographe, radiologie), \
implants, prothèses, instruments chirurgicaux, dispositifs de perfusion, \
défibrillateurs, ventilateurs, moniteurs, DM-DIV, réactifs de laboratoire
   - facturation           : CCAM, NGAP, tarifs, cotations, honoraires, remboursement actes
   - administratif         : obligations déclaratives, formations DPC, certifications, accréditations
   - sante_publique        : dépistage, vaccination, épidémies, prévention, plans nationaux
   - exercice              : convention médicale, installation, déserts médicaux, gardes, \
télémédecine, statut libéral, logiciels métier (LAP, DMP, DxCare…)

   RÈGLES DE DISCRIMINATION (prioritaires sur les définitions ci-dessus) :
   - Molécule / DCI / spécialité pharmaceutique nommée / AMM → 'medicament'
   - Équipement, matériel, appareil, dispositif médical (y compris imagerie) → 'dispositifs_medicaux'
   - Logiciel métier santé (LAP, DxCare, NETSoins, Cortexte, DMP) → 'exercice'
   - "Médicament" ou "dispositif" sont des mots-clés discriminants : \
     si le texte ne porte pas sur une molécule précise, ne pas utiliser 'medicament'

   Exemples corrects :
       Alerte ANSM paracétamol 1 g          → medicament
       Retrait AMM Valsartan                → medicament
       Alerte ANSM scanner Siemens          → dispositifs_medicaux
       Alerte ANSM IRM Philips              → dispositifs_medicaux
       Alerte ANSM bistouri / prothèse      → dispositifs_medicaux
       Alerte ANSM DxCare (logiciel)        → exercice
       Obligation utilisation LAP DMP       → exercice

7. TYPE DE PRATICIEN (type_praticien) — Détermine le profil professionnel PRINCIPALEMENT \
concerné par ce texte. Choisis parmi :
   - "prescripteur"    : médecins qui prescrivent des médicaments en ambulatoire \
     (MG, internistes, cardiologues, pneumologues, endocrinologues…). \
     Exemples : alerte pharmacovigilance, nouvelle indication médicamenteuse, \
     modification de remboursement d'un médicament de ville.
   - "interventionnel" : praticiens qui réalisent des actes techniques invasifs \
     (chirurgiens toutes sous-spécialités, anesthésiologistes, radiologues interventionnels). \
     Exemples : alertes sur dispositifs implantables, prothèses, fils de suture, \
     matériel de bloc opératoire, cotations CCAM d'actes chirurgicaux, \
     recommandations HAS sur gestes techniques ou protocoles per-opératoires.
   - "biologiste"      : biologistes médicaux (analyses biologiques, réactifs, automates de labo).
   - "pharmacien"      : pharmaciens d'officine (substitution, ruptures de stock officine, \
     règles de dispensation, convention pharmacien).
   - "tous"            : tous les praticiens libéraux sans distinction \
     (textes sur la convention médicale générale, tiers-payant, exercice libéral).

   RÈGLE CHIRURGIENS — Un texte portant sur des MÉDICAMENTS oraux ou injectables \
   prescrits en ville (alertes pharmacovigilance, nouvelles indications, remboursements) \
   → type_praticien = "prescripteur". \
   Le chirurgien N'EST PAS le destinataire principal même si la molécule est utilisée \
   en lien avec une pathologie chirurgicale.

   Un texte portant sur du matériel chirurgical (implants, prothèses, fils de suture, \
   instrumentation de bloc, robots chirurgicaux) \
   → type_praticien = "interventionnel".

   Exemples corrects :
     Alerte ANSM paracétamol 1 g (surdosage)         → prescripteur
     Alerte ANSM prothèse de hanche (débris métalliques) → interventionnel
     Arrêté honoraires convention médicale            → tous
     Rupture stock amoxicilline (consigne officine)   → pharmacien
     Automate PCR laboratoire                         → biologiste

IMPORTANT : réponds UNIQUEMENT avec un objet JSON valide, sans markdown, \
sans explication autour.
"""

# ---------------------------------------------------------------------------
# Prompt utilisateur
# ---------------------------------------------------------------------------

def _build_user_prompt(
    title: str,
    content: str | None,
    date_pub: str,
    source_hint: str | None = None,
) -> str:
    """
    source_hint : indication sur la provenance (ex: "ANSM alerte sécurité",
    "HAS recommandation", "JORF décret") pour aider Claude à contextualiser.
    """
    source_line = f"\nSOURCE : {source_hint}" if source_hint else ""
    content_section = ""
    if content and len(content.strip()) > 50:
        excerpt = content.strip()[:3000]
        content_section = f"\n\nEXTRAIT :\n{excerpt}"

    return f"""\
Analyse ce texte et retourne UNIQUEMENT le JSON demandé.

TITRE : {title}
DATE : {date_pub}{source_line}{content_section}

JSON attendu (strict, pas de markdown) :
{{
  "pertinent": <bool>,
  "audience": "<TRANSVERSAL_LIBERAL|SPECIALITE|PHARMACIENS>",
  "specialites": [<slugs parmi: medecine-generale, cardiologie, dermatologie, endocrinologie, gastro-enterologie, gynecologie, neurologie, ophtalmologie, orl, pediatrie, pneumologie, psychiatrie, rhumatologie, urologie, medecine-interne, medecine-urgences, geriatrie, medecine-physique, oncologie, hematologie, infectiologie, nephrologie, radiologie, anesthesiologie, chirurgie, chirurgie-vasculaire, chirurgie-orthopedique, chirurgie-thoracique, chirurgie-plastique, neurochirurgie, chirurgie-pediatrique, chirurgie-cardiaque, infirmiers, kinesitherapie, sage-femme, biologiste>],
  "type_praticien": "<prescripteur|interventionnel|biologiste|pharmacien|tous>",
  "score_density": <int 1-10>,
  "categorie": "<clinique|medicament|dispositifs_medicaux|facturation|administratif|sante_publique|exercice>",
  "tri_json": {{
    "titre_court": "<≤12 mots>",
    "resume": "<2-3 phrases concrètes>",
    "impact_pratique": "<1 phrase : que faire / retenir>",
    "nature": "<ARRETE|DECRET|LOI|ORDONNANCE|RECOMMANDATION|ALERTE|AVENANT|CIRCULAIRE|AUTRE>",
    "date_publication": "{date_pub}"
  }},
  "lecture_json": {{
    "points_cles": ["<bullet 1>", "..."],
    "texte_long": "<~150 mots>",
    "references": ["<NOR, ref légale, numéro AMM...>"]
  }}
}}
"""

# ---------------------------------------------------------------------------
# Mapping source → hint contextuel pour Claude
# ---------------------------------------------------------------------------

SOURCE_HINTS: dict[str, str] = {
    "legifrance_jorf":   "JORF — texte réglementaire (loi, décret, arrêté)",
    "piste_kali":        "Convention collective / accord UNCAM — impact sur honoraires et pratique libérale",
    "has_rbp":           "HAS — Recommandation de bonne pratique clinique",
    "ansm_securite":     "ANSM — Information de sécurité (pharmacovigilance, matériovigilance)",
    "ansm_securite_med": "ANSM — Alerte sécurité médicament (retrait AMM, contre-indication, restriction)",
    "ansm_ruptures_med": "ANSM — Rupture ou tension d'approvisionnement médicament",
    "ansm_ruptures_vaccins": "ANSM — Disponibilité vaccins",
    "bo_social":         "Bulletin officiel ministères sociaux — circulaire ou instruction ministère Santé",
}

# ---------------------------------------------------------------------------
# Appel Claude async (Anthropic SDK — utilisé par le batch script)
# ---------------------------------------------------------------------------

async def call_claude_async(
    title: str,
    content: str | None,
    date_pub: str,
    source: str | None = None,
    max_retries: int = 3,
) -> dict[str, Any]:
    """Appel Anthropic async avec retry exponentiel sur 429/timeout."""
    source_hint = SOURCE_HINTS.get(source or "", None)
    user_prompt = _build_user_prompt(title, content, date_pub, source_hint)
    client = _get_anthropic_client()

    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            response = await client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=ANTHROPIC_MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            raw_text = response.content[0].text
            return _parse_llm_output(raw_text)

        except anthropic.RateLimitError as e:
            last_error = e
            wait = 5 * (3 ** attempt)  # 5s, 15s, 45s
            logger.warning("Anthropic 429 (tentative %d/%d) — attente %ds", attempt + 1, max_retries, wait)
            await asyncio.sleep(wait)

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            last_error = e
            logger.warning("Parsing JSON échoué (tentative %d/%d): %s", attempt + 1, max_retries, e)
            if attempt == max_retries - 1:
                raise ValueError(f"json_parse_error: {e}") from e

        except Exception as e:
            last_error = e
            wait = 2 ** attempt
            logger.warning("Anthropic erreur (tentative %d/%d) — %s", attempt + 1, max_retries, e)
            await asyncio.sleep(wait)

    raise ValueError(f"Échec après {max_retries} tentatives: {last_error}")


async def analyse_candidate_async(
    candidate_id: str,
    title_raw: str,
    content_raw: str | None,
    official_date: str,
    source: str | None = None,
) -> dict[str, Any]:
    result = await call_claude_async(title_raw, content_raw, official_date, source=source)
    result["llm_model"]    = ANTHROPIC_MODEL
    result["candidate_id"] = candidate_id
    return result


# ---------------------------------------------------------------------------
# Configuration par source — seuils LLM pour créer un item
# ---------------------------------------------------------------------------

SOURCE_CONFIG: dict[str, dict] = {
    "legifrance_jorf": {
        "require_whitelist": True,   # titre doit contenir un terme santé
        "min_llm_score": 6,          # score_density LLM >= 6 pour créer un item
    },
    "ansm_securite": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    "ansm_securite_med": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    "ansm_ruptures_med": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "ansm_ruptures_vaccins": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "bo_social": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    "has_rbp": {
        "require_whitelist": False,
        "min_llm_score": 5,          # recommandations HAS à 5/10 restent utiles
    },
    "piste_kali": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
}

_DEFAULT_SOURCE_CONFIG = {"require_whitelist": False, "min_llm_score": 5}


def get_source_config(source: str | None) -> dict:
    return SOURCE_CONFIG.get(source or "", _DEFAULT_SOURCE_CONFIG)


# ---------------------------------------------------------------------------
# Whitelist JORF — au moins un terme santé doit apparaître dans le titre
# ---------------------------------------------------------------------------

_JORF_WHITELIST_PATTERNS = [
    # Professions de santé
    r"(?i)\bmédecin\b", r"(?i)\bmédicale?\b", r"(?i)\bpharmacie\b", r"(?i)\bpharmacien\b",
    r"(?i)\binfirmier", r"(?i)\bsage-femme\b", r"(?i)\bkinésithér", r"(?i)\bbiologiste\b",
    r"(?i)\bchirurgien\b", r"(?i)\bchirurgie\b", r"(?i)\bdentiste\b", r"(?i)\bodontolog",
    r"(?i)\borthophoniste\b", r"(?i)\borthoptiste\b", r"(?i)\bpodologue\b",
    r"(?i)\bpsychiatr", r"(?i)\bpsycholog",
    # Médicaments & dispositifs
    r"(?i)\bmédicament\b", r"(?i)\bspécialités? pharmaceutiques?\b", r"(?i)\bAMM\b",
    r"(?i)\bpharmacovigilance\b", r"(?i)\bsubstance\b",
    r"(?i)\bdispositif médical\b", r"(?i)\bmatériovigilance\b",
    r"(?i)\bvaccin", r"(?i)\bvaccination\b",
    # Remboursement & financement
    r"(?i)\bremboursement\b", r"(?i)\bnomenclature\b", r"(?i)\bcotation\b",
    r"(?i)\bhonoraires\b", r"(?i)\btarif\b", r"(?i)\bCPAM\b",
    r"(?i)\bassurance.maladie\b", r"(?i)\bsécurité sociale\b",
    r"(?i)\bconvention médicale\b", r"(?i)\bUNCAM\b",
    r"(?i)\bprescription\b", r"(?i)\bordonnance\b",
    # Système de santé
    r"(?i)\bsanté publique\b", r"(?i)\bétablissement de santé\b",
    r"(?i)\bhospitalier\b", r"(?i)\bclinique\b",
    r"(?i)\bARS\b", r"(?i)\bagence régionale de santé\b",
    r"(?i)\bprofessionnel de santé\b", r"(?i)\bexercice libéral\b",
    r"(?i)\btéléconsultation\b", r"(?i)\btelemédecine\b",
    r"(?i)\bprise en charge\b",
    # Pathologies / actes
    r"(?i)\bpatient\b", r"(?i)\bsoins\b", r"(?i)\bthérapeutique\b",
    r"(?i)\bcancer\b", r"(?i)\boncolog", r"(?i)\btumeur\b",
    r"(?i)\bcardiolog", r"(?i)\bneurolog", r"(?i)\bpédiatrie\b",
    r"(?i)\bmaternité\b", r"(?i)\bgrossesse\b", r"(?i)\baccouchement\b",
    r"(?i)\bdouleur\b", r"(?i)\banesthés",
]
_JORF_WHITELIST_RES = [re.compile(p) for p in _JORF_WHITELIST_PATTERNS]


def _passes_jorf_whitelist(title: str) -> bool:
    return any(p.search(title) for p in _JORF_WHITELIST_RES)


# ---------------------------------------------------------------------------
# Pré-filtre local (0 appel API)
# ---------------------------------------------------------------------------

_DROP_TITLE_PATTERNS = [
    # ── Nominations / RH ────────────────────────────────────────────────────
    r"(?i)\bnomination\b",
    r"(?i)portant nomination",
    r"(?i)\bavis de vacance",
    r"(?i)portant promotion de grade",
    r"(?i)portant d[eé]tachement",
    r"(?i)portant placement en disponibilit",
    r"(?i)portant titularisation",
    r"(?i)portant naturalisation",
    r"(?i)portant r[eé]int[eé]gration",
    r"(?i)portant radiation",
    r"(?i)portant d[eé]l[eé]gation de signature",
    r"(?i)\btableau d.avancement\b",
    r"(?i)\bliste d.aptitude\b",
    r"(?i)\bconcours\b",
    r"(?i)\bdocuments? déposés?",
    r"(?i)\brésultats? d[eu']",
    r"(?i)désignation d.un",
    r"(?i)cessation de fonctions?",
    r"(?i)admission à la retraite",
    # ── Justice / Magistrature ───────────────────────────────────────────────
    r"(?i)\bmagistrat(ure)?\b",
    r"(?i)tribunal administratif",
    r"(?i)cour administrative d.appel",
    r"(?i)conseil d.[eé]tat",
    r"(?i)d[eé]tachement judiciaire",
    # ── Militaire / Sécurité ────────────────────────────────────────────────
    r"(?i)\bofficier\b",
    r"(?i)\bsous-officier\b",
    r"(?i)\bgendarmerie\b",
    r"(?i)\barm[eé]e de\b",
    r"(?i)\bmarine nationale\b",
    r"(?i)\barmement\b",
    r"(?i)\bcote\s*&\s*score",
    r"(?i)\bmédaille\b",
    r"(?i)\bdécoration\b",
    r"(?i)\blégion d.honneur",
    r"(?i)\bordre national du mérite",
    # ── Divers hors scope ───────────────────────────────────────────────────
    r"(?i)\bjury\b",
    r"(?i)\bélection\b",
    r"(?i)\bassesseur\b",
    r"(?i)commission de discipline",
    r"(?i)administration p[eé]nitentiaire",
    r"(?i)\bpr[eé]fecture\b",
    r"(?i)\bambassadeur\b",
    r"(?i)\bconsulat\b",
    r"(?i)commissaire du gouvernement",
    r"(?i)contrôleur général",
    r"(?i)radiation des cadres",
]
_DROP_TITLE_RES = [re.compile(p) for p in _DROP_TITLE_PATTERNS]

# Dispositifs médicaux non-médicamenteux — hors scope de tous les praticiens libéraux.
# NB : prothèses, implants, robots chirurgicaux, instruments de bloc sont CONSERVÉS
#      car ils concernent les chirurgiens libéraux. Le filtrage fin est géré par
#      type_praticien dans le pipeline LLM.
_ANSM_DM_EXCLUDE_PATTERNS = [
    # ── Équipements de confort / hôpital (non-clinique) ─────────────────────
    r"(?i)\bfauteuil roulant\b",
    r"(?i)\bdéambulateur\b",
    r"(?i)\blit médical\b",
    r"(?i)\bmatelas\b",
    r"(?i)\bcoussin\b",
    # ── Perfusion / pompes externes (DM hôpital, hors libéral) ──────────────
    r"(?i)\bdispositif de perfusion\b",
    r"(?i)\bpompe à insuline externe\b",
    r"(?i)\bpompe externe\b",
    # ── Monitoring / imagerie (DM institution, alerte biomédicale) ──────────
    r"(?i)\béchographe\b",
    r"(?i)\bscanner\b",
    r"(?i)\bIRM\b",
    r"(?i)\bmonitorage\b",
    r"(?i)\bsystème de monitorage\b",
    r"(?i)\bkwik-stik\b",
    r"(?i)\blyfo disk\b",
    r"(?i)\bbactériologie.*contrôle\b",
    r"(?i)\bcontrôle.*bactériologie\b",
    # ── Diagnostic in vitro / réactifs de laboratoire ────────────────────────
    r"(?i)\bréactif\b",
    r"(?i)dispositif de diagnostic in vitro",
    r"(?i)\bDM-DIV\b",
    r"(?i)\bautomate\b",
    r"(?i)\banalyseur\b",
    r"(?i)\bconsommable\b",
    r"(?i)réactif de laboratoire",
    r"(?i)kit de d[eé]tection",
    r"(?i)\bPCR\b",
    r"(?i)test rapide",
    r"(?i)\bbandelette\b",
]
_ANSM_DM_EXCLUDE_RES = [re.compile(p) for p in _ANSM_DM_EXCLUDE_PATTERNS]

_ANSM_SOURCES = {"ansm_securite", "ansm_securite_med", "ansm_ruptures_med", "ansm_ruptures_vaccins"}


def pre_filter_candidate(title: str, source: str | None = None) -> tuple[bool, str | None]:
    """Retourne (keep, reason). Si keep=False, pas besoin d'appel LLM."""
    t = (title or "").strip()
    if not t:
        return False, "empty_title"
    for pat in _DROP_TITLE_RES:
        if pat.search(t):
            return False, f"drop_title:{pat.pattern}"
    # Exclusion ANSM dispositifs médicaux non-médicamenteux
    if source in _ANSM_SOURCES:
        for pat in _ANSM_DM_EXCLUDE_RES:
            if pat.search(t):
                return False, f"ansm_dm:{pat.pattern}"
    # Whitelist JORF : titre doit contenir au moins un terme santé
    cfg = get_source_config(source)
    if cfg.get("require_whitelist") and not _passes_jorf_whitelist(t):
        return False, "jorf_no_health_term"
    return True, None


# ---------------------------------------------------------------------------
# Appel Claude sync — wrapper sur l'async (utilisé par FastAPI routes)
# ---------------------------------------------------------------------------

def call_claude(
    title: str,
    content: str | None,
    date_pub: str,
    source: str | None = None,
    max_retries: int = 3,
) -> dict[str, Any]:
    """Wrapper sync sur call_claude_async.

    Utilise un ThreadPoolExecutor pour lancer asyncio.run() dans un thread
    dédié, ce qui évite le RuntimeError quand appelé depuis un event loop
    déjà en cours (routes FastAPI async).
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            asyncio.run,
            call_claude_async(title, content, date_pub, source=source, max_retries=max_retries),
        )
        return future.result()


# ---------------------------------------------------------------------------
# Parsing + validation
# ---------------------------------------------------------------------------

def _extract_json_block(text: str) -> str:
    """Extrait le premier bloc JSON complet (accolades équilibrées)."""
    start = text.find("{")
    if start == -1:
        raise ValueError("Pas de '{' trouvé")
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text[start:], start):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("JSON non fermé")


def _parse_llm_output(raw: str) -> dict[str, Any]:
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    json_str = _extract_json_block(cleaned)
    # Corriger les valeurs d'enum non quotées (ex: audience: PHARMACIENS → "PHARMACIENS")
    json_str = re.sub(
        r'("audience"\s*:\s*)([A-Z_]+)(\s*[,}])',
        lambda m: f'{m.group(1)}"{m.group(2)}"{m.group(3)}',
        json_str,
    )
    data = json.loads(json_str)

    if not isinstance(data.get("pertinent"), bool):
        raise ValueError("Champ 'pertinent' manquant ou invalide")

    audience = data.get("audience", "")
    if audience not in KNOWN_AUDIENCES:
        data["audience"] = "TRANSVERSAL_LIBERAL"

    raw_slugs = data.get("specialites", [])
    data["specialites"] = [s for s in raw_slugs if s in KNOWN_SPECIALTIES]

    if data.get("type_praticien") not in KNOWN_TYPE_PRATICIEN:
        # Infer from audience/specialites if Claude missed it
        aud = data.get("audience", "")
        specs = data.get("specialites", [])
        if aud == "PHARMACIENS":
            data["type_praticien"] = "pharmacien"
        elif any(s.startswith("chirurgie") or s in ("anesthesiologie", "neurochirurgie") for s in specs):
            data["type_praticien"] = "interventionnel"
        elif aud == "TRANSVERSAL_LIBERAL":
            data["type_praticien"] = "tous"
        else:
            data["type_praticien"] = "prescripteur"

    try:
        data["score_density"] = max(1, min(10, int(data.get("score_density", 5))))
    except (TypeError, ValueError):
        data["score_density"] = 5

    KNOWN_CATEGORIES = {"clinique", "medicament", "dispositifs_medicaux", "facturation", "administratif", "sante_publique", "exercice"}
    if data.get("categorie") not in KNOWN_CATEGORIES:
        data["categorie"] = None  # sera assigné rétroactivement

    if not isinstance(data.get("tri_json"), dict):
        data["tri_json"] = {}
    if not isinstance(data.get("lecture_json"), dict):
        data["lecture_json"] = {}

    return data


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

def analyse_candidate(
    candidate_id: str,
    title_raw: str,
    content_raw: str | None,
    official_date: str,
    source: str | None = None,
    llm_model: str = ANTHROPIC_MODEL,
) -> dict[str, Any]:
    """
    Analyse un candidat et retourne un dict prêt pour la table items.
    Lève une exception si l'appel LLM échoue.
    """
    result = call_claude(title_raw, content_raw, official_date, source=source)
    result["llm_model"]    = llm_model
    result["candidate_id"] = candidate_id
    return result
