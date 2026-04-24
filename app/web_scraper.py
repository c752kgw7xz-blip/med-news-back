# app/web_scraper.py
"""
Collecteur HTML — sociétés savantes sans flux RSS.

Stratégie : scrape la page "publications/recommandations" de chaque société,
extrait les liens vers des documents récents, insère en base via le même
pipeline que le collecteur RSS.

Deux périmètres couverts :
  1. Sources FR  (WEB_SCRAPER_SOURCES)  : SFH, SFR, SFO, SFPédiatrie, SOFCOT, SOFMER, SOFCPRE plastique
  2. Sources EUR (EUROPE_WEB_SOURCES)   : ESC, EULAR, EAU, ESCMID, EAN, ECCO, EHA,
                                          EASD, ESE, ERA — priorité médico-légale haute

Volume attendu : 2-10 documents/an par société → collecte trimestrielle suffit.
Les guidelines européennes passent partiellement via les feeds RSS déjà actifs
(ESMO, ERS, EASL, ESICM, ESO, ESVS, EADV...), mais ESC/EULAR/EAU/ESCMID
sont UNIQUEMENT couverts par ce scraper — ne pas les ignorer.
"""

from __future__ import annotations

from app.sources import EU_WEB_SOURCES as EUROPE_WEB_SOURCES

import logging
import re
from datetime import date
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Best-effort date extraction from title/link text
# ---------------------------------------------------------------------------

_MONTH_FR: dict[str, int] = {
    "janvier": 1, "février": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
    "juillet": 7, "août": 8, "septembre": 9, "octobre": 10, "novembre": 11, "décembre": 12,
    "jan": 1, "fev": 2, "fév": 2, "avr": 4, "juil": 7, "sept": 9, "oct": 10, "nov": 11, "déc": 12,
}
_MONTH_EN: dict[str, int] = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_ALL_MONTHS = {**_MONTH_FR, **_MONTH_EN}
_MONTH_PATTERN = "|".join(re.escape(m) for m in sorted(_ALL_MONTHS, key=len, reverse=True))

# "March 2025", "mars 2024", "septembre 2025", "Feb 2024"
_RE_MONTH_YEAR = re.compile(rf"(?i)\b({_MONTH_PATTERN})\s+(\d{{4}})\b")
# Standalone 4-digit year (2020-2029)
_RE_YEAR = re.compile(r"\b(20[2-3]\d)\b")


def _extract_date_from_title(title: str) -> date | None:
    """Try to extract a publication date from the title text (best-effort)."""
    # Try month + year first
    m = _RE_MONTH_YEAR.search(title)
    if m:
        month_name = m.group(1).lower()
        year = int(m.group(2))
        month = _ALL_MONTHS.get(month_name)
        if month and 2020 <= year <= date.today().year + 1:
            return date(year, month, 1)

    # Fallback: standalone year → January 1st of that year
    m = _RE_YEAR.search(title)
    if m:
        year = int(m.group(1))
        if 2020 <= year <= date.today().year + 1:
            return date(year, 1, 1)

    return None

import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn
from app.llm_analysis import pre_filter_candidate

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "fr-FR,fr;q=0.9",
}


# ---------------------------------------------------------------------------
# Configuration des sources à scraper
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Sources de congrès vasculaires — highlights & late-breaking data
# ---------------------------------------------------------------------------
# Ces sources publient les résultats de congrès avant les journaux académiques.
# Volume : 10-30 highlights par édition (1-2x/an). Scrape mensuel suffit.
# min_score_hint=7 : on ne retient que les vraies nouvelles cliniques
# (nouveau dispositif, RCT pivot, changement de guideline).

VASCULAR_CONGRESS_SOURCES: list[dict] = [
    # ── Congrès vasculaires — scraping désactivé (voir note ci-dessous) ───
    #
    # LINC Leipzig (linc-society.com) : domaine NXDOMAIN depuis avril 2026.
    #   → couvert en temps réel par TCTMD (tctmd.com/feed) et Vascular News.
    #
    # CIRSE (cirse.org) : RSS vide, site JS-rendered. Library (library.cirse.org)
    #   requiert authentification. Highlights couverts par TCTMD.
    #
    # ESVS (esvs.org) : RSS actif mais uniquement contenu administratif
    #   (appels à candidatures, comités). Guidelines = via pubmed_ejves.
    #
    # EVC (escardio.org/EVC) : hors cible chirurgie vasculaire.
    #
    # Solution retenue : TCTMD + Vascular News + Endovascular Today couvrent
    # tous les congrès majeurs (LINC, CIRSE, VEITH, VAM, ESVS AM) en temps réel.
    # Ce bloc est conservé comme placeholder pour une réactivation future si
    # un domaine LINC devient stable.
]

WEB_SCRAPER_SOURCES: list[dict] = [

    # ── SFH — Société Française d'Hématologie ────────────────────────────
    # Page statique listant les recommandations publiées par la SFH.
    # Volume : ~2-5 recommandations/an. Scrape trimestriel recommandé.
    {
        "url": "https://sfh.hematologie.net/professionnel/recommandations",
        "source": "sfh",
        "label": "SFH — Recommandations hématologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "hematologie",
        # Inclure tous les liens internes + externes sur cette page
        "link_pattern": r".+",
        # Exclure les liens de navigation pure
        "exclude_pattern": r"/(la-sfh|adhesion|annuaire|contactez|elections|statuts|bureau|congres|subvention|bourse|du-diu|enseignement|formation-micro|cnu|des\b|mediatheque|annonces-d-emploi|patients)(/|$)",
    },

    # ── SFR — Société Française de Radiologie ────────────────────────────
    # Section "Revues & Publications" du site SFR.
    # Inclut les recommandations de pratiques professionnelles (guides GRADE).
    {
        "url": "https://www.radiologie.fr/revues-publications",
        "source": "sfr_radiologie",
        "label": "SFR — Revues & Publications radiologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "radiologie",
        "link_pattern": r"radiologie\.fr/",
        "exclude_pattern": r"/(la-sfr|congres|formation|bourses|agenda|musee|junior|delegations|instances|societes-d-organe|patient\.radiologie)(/|$)",
    },

    # ── SFO — Société Française d'Ophtalmologie ──────────────────────────
    # Page Actualités (publique) — contient ruptures d'approvisionnement,
    # alertes ANSM relayées, arrêts de commercialisation de collyres/pommades,
    # recommandations antibioprophylaxie en chirurgie ophtalmologique.
    # /publications/rapports est DERRIÈRE LOGIN — scraper y récupère zéro.
    {
        "url": "https://www.sfo-online.fr/actualites",
        "source": "sfo",
        "label": "SFO — Actualités ophtalmologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "link_pattern": r"sfo-online\.fr/",
        "exclude_pattern": r"(?i)/(agenda|annuaire|adhesion|contacts|congres|assemblee-generale|hommage|disparition|election|jeunes-ophtalmos|comptes-annuels|mediatheque)(/|$)",
    },

    # ── SOFMER désactivé — avril 2026 ────────────────────────────────────────
    # La page sofmer.com/?pageID=sf23_sofmer_collab est une archive statique
    # de PDFs anciens (coiffe des rotateurs, ménisques, etc. datant de 2012-2016).
    # Le scraper les collecte avec la date du jour → la règle ancienneté ne
    # se déclenche pas → pollue la file de review avec du contenu obsolète.
    # Le RSS SOFMER est également désactivé (404 depuis mars 2026).
    # À réactiver uniquement si SOFMER ouvre une page d'actualités datées.

    # ── SFPédiatrie ───────────────────────────────────────────────────────
    # Page des recommandations/mises au point de la SFP.
    {
        "url": "https://www.sfpediatrie.com/ressources/recommandationsmises-au-point",
        "source": "sfpediatrie",
        "label": "SFP — Recommandations pédiatrie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "pediatrie",
        "link_pattern": r"sfpediatrie\.com/",
        "exclude_pattern": r"/(la-sfp|adhesion|agenda|congres|bourses|formation|annuaire|nous-contacter|actualites/agenda)(/|$)",
    },

    # ── GPIP — déplacé vers sources_europe.py (RSS WordPress /feed/) ────────
    # gpip.fr expose un feed WordPress valide → collecté via rss_collector.
    # Source : "gpip" dans ALL_EUROPE_FEEDS.

    # ── SOFCOT — Société Française de Chirurgie Orthopédique ─────────────
    # Actualités / publications de la SOFCOT.
    {
        "url": "https://www.sofcot.fr/publications",
        "source": "sofcot",
        "label": "SOFCOT — Publications orthopédie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-orthopedique",
        "link_pattern": r"sofcot\.fr/",
        "exclude_pattern": r"/(la-sofcot|adhesion|agenda|congres|bourses|formation|annuaire|contact|accueil)(/|$)",
    },

    # ── EUPSA / SFCP — supprimées (aucune page de guidelines publique accessible)
    # EUPSA (eupsa.info) : pas de page guidelines publique — output dans JPS/PSI/EJPS
    # SFCP (chirurgie-pediatrique.com) : portail membres Wix, contenu non indexable

    # ── SOFCPRE — Société Française de Chirurgie Plastique Reconstructrice ──
    # Seule page publique avec contenu clinique sur sofcpre.fr.
    # Le RSS sofcpre.fr/feed/ est 404 depuis mars 2026. Le site est quasi-statique
    # (dernier contenu connu : 2020), MAIS le scraper tournera trimestriellement
    # et capturera automatiquement tout nouveau document ajouté.
    # Contenu actuel : recommandations CCAM, registre implants, COVID (2020).
    # Contenu futur attendu : recommandations BIA-ALCL, implants mammaires, CCAM
    # chirurgie plastique, recommandations techniques esthétiques.
    # Alternative principale : pubmed_acpe (ACPE = journal officiel SOFCPRE).
    # Vérifié actif : sofcpre.fr/recommandations.html → 200 (avril 2026).
    {
        "url": "https://www.sofcpre.fr/recommandations.html",
        "source": "sofcpre_plastique",
        "label": "SOFCPRE — Recommandations chirurgie plastique reconstructrice et esthétique",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "chirurgie-plastique",
        # Inclure les liens internes sofcpre.fr et les liens PDF/HAS/ANSM référencés
        "link_pattern": r"(sofcpre\.fr|has-sante\.fr|ansm\.sante\.fr|solidarites-sante\.gouv\.fr)",
        # Exclure navigation, annuaire chirurgiens, mentions légales
        "exclude_pattern": r"/(chirurgiens/|identification|accueil|$)",
    },

    # ── INCa — Institut National du Cancer ───────────────────────────────
    # Seule source nationale pour les recommandations et référentiels en
    # oncologie : thésaurus de traitement (chimiothérapies, protocoles RCP),
    # recommandations de bonne pratique clinique (RBP), référentiels nationaux
    # labellisés, guides de prise en charge spécialisée.
    #
    # Domaine : cancer.fr (alias de e-cancer.fr, sans problème de certificat SSL)
    # Page : catalogue des publications — statique HTML, pas de JS requis.
    # Volume : ~10-20 nouvelles recommandations/référentiels par an.
    # Dédup : par URL → les publications déjà en base ne sont pas re-insérées.
    # Date : extraite du titre si disponible, sinon date du jour (acceptable
    #        car le pipeline déduplique et les pubs récentes sont les seules nouvelles).
    #
    # Pattern d'exclusion : dépliant, affiche, guide patient, rapport épidémio,
    # communiqué — contenu non clinique pour le praticien.
    {
        "url": "https://www.cancer.fr/catalogue-des-publications",
        "source": "inca_recommandations",
        "label": "INCa — Recommandations et référentiels nationaux en oncologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "oncologie",
        "link_pattern": r"cancer\.fr/catalogue-des-publications/\S+",
        "exclude_pattern": (
            r"(?i)/catalogue-des-publications/"
            r"(depliant|affiche|brochure|guide-patient|guide-du-patient"
            r"|sante-des-femmes|defis-cancer|chiffres-cles|bilan-d-activite"
            r"|rapport-annuel|communique|lettre-|newsletter|agenda|evenement"
            r"|appel-a-projets|annonce|emploi|formation|kit-de-communication"
            r"|poster|flyer|infographie)"
        ),
        "min_score_hint": 6,
    },
]


# ---------------------------------------------------------------------------
# Parser HTML léger (stdlib, sans dépendance externe)
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Extrait tous les liens <a href="..."> d'un document HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[tuple[str, str]] = []   # (href, text)
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            attr_dict = dict(attrs)
            href = attr_dict.get("href") or ""
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self._current_href = urljoin(self.base_url, href)
                self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href:
            text = " ".join(self._current_text).strip()
            text = re.sub(r"\s+", " ", text)
            if text:
                self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


def _extract_links(html: str, base_url: str) -> list[tuple[str, str]]:
    """Retourne une liste de (url, titre) extraits d'un document HTML."""
    parser = _LinkExtractor(base_url)
    parser.feed(html)
    return parser.links


# ---------------------------------------------------------------------------
# Collecteur d'une source HTML
# ---------------------------------------------------------------------------

def scrape_source(config: dict) -> dict[str, int]:
    """
    Scrape une page web, extrait les liens correspondant au pattern configuré,
    applique le pré-filtre, insère les nouveaux candidats en base.

    Retourne des stats : seen / inserted / deduped / skipped.
    """
    url     = config["url"]
    source  = config["source"]
    label   = config.get("label", source)
    link_re = re.compile(config.get("link_pattern", r".+"))
    excl_re = re.compile(config["exclude_pattern"]) if config.get("exclude_pattern") else None

    try:
        with httpx.Client(follow_redirects=True, timeout=20, headers=_HEADERS) as client:
            resp = client.get(url)
            resp.raise_for_status()
            html = resp.text
    except Exception as e:
        logger.warning("[%s] fetch échoué : %s", source, e)
        return {"seen": 0, "inserted": 0, "deduped": 0, "skipped": 0, "error": str(e)}

    raw_links = _extract_links(html, url)

    seen = inserted = deduped = skipped = 0
    today = date.today()

    # Dédupliquer par URL dans ce batch
    seen_urls: set[str] = set()

    with get_conn() as conn:
        with conn.cursor() as cur:
            for href, title in raw_links:
                seen += 1

                # 1. Pattern d'inclusion
                if not link_re.search(href):
                    skipped += 1
                    continue

                # 2. Pattern d'exclusion
                if excl_re and excl_re.search(href):
                    skipped += 1
                    continue

                # 3. Titre trop court pour être un article
                if len(title) < 10:
                    skipped += 1
                    continue

                # 4. Dédup intra-batch
                if href in seen_urls:
                    deduped += 1
                    continue
                seen_urls.add(href)

                # 5. Pré-filtre heuristique (même logique que RSS)
                keep, drop_reason = pre_filter_candidate(title, source=source)
                if not keep:
                    logger.debug("[%s] pre_filter DROP '%s' (%s)", source, title[:60], drop_reason)
                    skipped += 1
                    continue

                # Best-effort date extraction from title text
                pub_date = _extract_date_from_title(title) or today

                raw_payload: dict[str, Any] = {
                    "href": href,
                    "title": title,
                    "source_url": url,
                    "feed_source": source,
                    "feed_label": label,
                    "audience": config.get("audience", []),
                    "scraped_date": str(today),
                    "date_extracted": pub_date != today,
                }

                row = build_candidate_row(
                    source=source,
                    external_id=href,           # URL = identifiant stable
                    official_url=href,
                    official_date=pub_date,
                    title_raw=title,
                    content_raw=None,
                    raw_payload=raw_payload,
                )

                if insert_candidate(cur, row):
                    inserted += 1
                    logger.debug("[%s] INS '%s'", source, title[:70])
                else:
                    deduped += 1

        conn.commit()

    logger.info("[%s] vu=%d ins=%d dup=%d ign=%d", source, seen, inserted, deduped, skipped)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ---------------------------------------------------------------------------
# Collecteur global
# ---------------------------------------------------------------------------

def scrape_all_web(sources: list[dict] | None = None) -> dict[str, Any]:
    """
    Lance le scraping de toutes les sources HTML configurées (ou un sous-ensemble).
    Couvre :
      - Sources FR  (WEB_SCRAPER_SOURCES)       : SFH, SFR, SFO, SFPédiatrie, SOFCOT
      - Sources EUR (EUROPE_WEB_SOURCES)         : ESC, EULAR, EAU, ESCMID, EAN…
      - Congrès vasc. (VASCULAR_CONGRESS_SOURCES): LINC, EVC
    Volume faible → pas de parallélisme nécessaire.
    """
    targets = sources or (WEB_SCRAPER_SOURCES + EUROPE_WEB_SOURCES + VASCULAR_CONGRESS_SOURCES)
    results: dict[str, Any] = {}
    for config in targets:
        try:
            results[config["source"]] = scrape_source(config)
        except Exception as e:
            logger.error("[%s] erreur : %s", config["source"], e)
            results[config["source"]] = {"error": str(e)}
    return results


def scrape_europe_web() -> dict[str, Any]:
    """
    Lance uniquement le scraping des sources européennes sans RSS.
    Peut être appelé séparément via l'interface admin.
    """
    results: dict[str, Any] = {}
    for config in EUROPE_WEB_SOURCES:
        try:
            results[config["source"]] = scrape_source(config)
        except Exception as e:
            logger.error("[%s] erreur : %s", config["source"], e)
            results[config["source"]] = {"error": str(e)}
    return results
