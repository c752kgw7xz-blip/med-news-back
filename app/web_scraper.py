# app/web_scraper.py
"""
Collecteur HTML — sociétés savantes sans flux RSS.

Stratégie : scrape la page "publications/recommandations" de chaque société,
extrait les liens vers des documents récents, insère en base via le même
pipeline que le collecteur RSS.

Deux périmètres couverts :
  1. Sources FR  (WEB_SCRAPER_SOURCES)  : SFH, SFR, SFO, SFPédiatrie, SOFCOT, SOFCPRE plastique, INCa
  2. Sources EUR (EUROPE_WEB_SOURCES)   : ESC, EULAR, EAU, ESCMID, EAN, ECCO, EHA,
                                          EASD, ESE, ERA, ESGE, EuSEM, EFIM, EFLM, ESHRE,
                                          EGS, EURETINA, EFP, EAHP — priorité médico-légale haute

Volume attendu : 2-10 documents/an par société → collecte trimestrielle suffit.
Les guidelines européennes passent partiellement via les feeds RSS déjà actifs
(ESMO, ERS, EASL, ESICM, ESO, ESVS, EADV...), mais ESC/EULAR/EAU/ESCMID
sont UNIQUEMENT couverts par ce scraper — ne pas les ignorer.
"""

from __future__ import annotations

from app.sources import EU_WEB_SOURCES as EUROPE_WEB_SOURCES

import logging
import re
from datetime import date, timedelta
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
      - Sources FR  (WEB_SCRAPER_SOURCES)       : SFH, SFR, SFO, SFPédiatrie, SOFCOT, SOFCPRE, INCa
      - Sources EUR (EUROPE_WEB_SOURCES)         : ESC, EULAR, EAU, ESCMID, EAN, ESGE, EuSEM…
      - Congrès vasc. (VASCULAR_CONGRESS_SOURCES): désactivé (liste vide — couvert par TCTMD/VN)
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


# ---------------------------------------------------------------------------
# Scraper CNOM — Conseil National de l'Ordre des Médecins
# ---------------------------------------------------------------------------
# Le flux RSS du CNOM (rss.xml) retourne 0 entrées depuis début 2026.
# Ce scraper remplace le flux RSS en parcourant les sections de publications
# du site statique Drupal du CNOM.
#
# Sections couvertes :
#   - /publications/actualites            — actualités générales (exercice, déontologie)
#   - /publications/communiques-presse    — communiqués (positions réglementaires)
#   - /publications/documentation/fiches-pratiques — fiches praticien (exercice libéral)
#
# Structure HTML :
#   Listing : <a href="/publications/…">Titre</a> + date dans le container parent
#   Date    : "19 avril 2026" (texte français) → extraite par regex
#   Pagination : ?page=N (Drupal, base 0)
# ---------------------------------------------------------------------------

_CNOM_BASE = "https://www.conseil-national.medecin.fr"

_CNOM_SECTIONS: list[dict[str, str]] = [
    {
        "url": f"{_CNOM_BASE}/publications/actualites",
        "label": "Actualités",
    },
    {
        "url": f"{_CNOM_BASE}/publications/communiques-presse",
        "label": "Communiqués de presse",
    },
    {
        "url": f"{_CNOM_BASE}/publications/documentation/fiches-pratiques",
        "label": "Fiches pratiques",
    },
]

# Liens de navigation / section à exclure (pas d'articles)
_CNOM_EXCLUDE = re.compile(
    r"/publications/"
    r"(bulletins-lordre-medecins|communiques-presse|debats-lordre|documentation"
    r"|documentation/editions|documentation/rapports|documentation/fiches-pratiques"
    r"|documentation/analyses-etudes|newsletter|videos|webzines|actualites"
    r"|actualites/lanceur-dalerte)/?$"
)

# Regex date française dans le texte environnant
_FR_DATE_RE = re.compile(
    r"(\d{1,2})\s+(janvier|février|mars|avril|mai|juin|juillet|août"
    r"|septembre|octobre|novembre|décembre)\s+(\d{4})",
    re.IGNORECASE,
)
_FR_MONTHS = {
    "janvier": 1, "février": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
    "juillet": 7, "août": 8, "septembre": 9, "octobre": 10, "novembre": 11, "décembre": 12,
}


def _parse_fr_date(text: str) -> date | None:
    """Convertit '19 avril 2026' → date(2026, 4, 19). Retourne None si pas de match."""
    m = _FR_DATE_RE.search(text)
    if not m:
        return None
    day, month_name, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
    month = _FR_MONTHS.get(month_name)
    if not month:
        return None
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _cnom_extract_items(html: str, section_url: str) -> list[tuple[str, str, date | None]]:
    """
    Extrait les articles d'une page de listing CNOM.
    Retourne une liste de (url_absolue, titre, date_pub | None).
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    results: list[tuple[str, str, date | None]] = []
    seen_hrefs: set[str] = set()

    for a in soup.find_all("a", href=re.compile(r"^/publications/")):
        href = a.get("href", "")
        # Exclure liens de navigation pure
        if _CNOM_EXCLUDE.match(href):
            continue
        title = a.get_text(strip=True)
        if len(title) < 15:
            continue
        abs_url = _CNOM_BASE + href
        if abs_url in seen_hrefs:
            continue
        seen_hrefs.add(abs_url)

        # Chercher la date dans le container parent (jusqu'à 5 niveaux)
        pub_date: date | None = None
        container = a.parent
        for _ in range(5):
            if container is None:
                break
            txt = container.get_text()
            pub_date = _parse_fr_date(txt)
            if pub_date:
                break
            container = container.parent

        results.append((abs_url, title, pub_date))

    return results


def collect_cnom(days: int = 180, max_pages: int = 5) -> dict[str, Any]:
    """
    Scrape les publications du CNOM (actualités, communiqués, fiches pratiques).
    Insère les articles récents (dans la fenêtre `days`) en tant que candidates
    avec source='cnom' et source_type='reglementaire'.

    Args:
        days: Fenêtre temporelle en arrière depuis aujourd'hui.
        max_pages: Nombre maximum de pages par section (Drupal page=0..N-1).

    Returns:
        Dict de stats : seen / inserted / deduped / skipped / too_old.
    """
    source = "cnom"
    today = date.today()
    cutoff = today - timedelta(days=days)

    seen = inserted = deduped = skipped = too_old = 0

    with httpx.Client(follow_redirects=True, timeout=20, headers=_HEADERS) as client:
        with get_conn() as conn:
            with conn.cursor() as cur:
                for section in _CNOM_SECTIONS:
                    section_url = section["url"]
                    section_label = section["label"]

                    # Résoudre la redirection Drupal pour obtenir l'URL canonique
                    # (/publications/actualites → /publications?categories[]=28)
                    # La pagination doit s'appliquer à l'URL finale, pas à l'URL canonique.
                    try:
                        resp0 = client.get(section_url)
                        resp0.raise_for_status()
                        canonical_url = str(resp0.url)  # URL après redirections
                    except Exception as e:
                        logger.warning("[cnom] fetch section %s : %s", section_url, e)
                        continue

                    for page in range(max_pages):
                        # Construire l'URL paginée à partir de l'URL canonique
                        if page == 0:
                            url = canonical_url
                            resp = resp0  # déjà fetchée
                        else:
                            sep = "&" if "?" in canonical_url else "?"
                            url = f"{canonical_url}{sep}page={page}"
                            try:
                                resp = client.get(url)
                                resp.raise_for_status()
                            except Exception as e:
                                logger.warning("[cnom] fetch %s : %s", url, e)
                                break

                        items = _cnom_extract_items(resp.text, section_url)
                        if not items:
                            logger.debug("[cnom] page vide : %s", url)
                            break

                        page_has_recent = False

                        for abs_url, title, pub_date in items:
                            seen += 1

                            # Filtrer par date si connue
                            if pub_date:
                                if pub_date < cutoff:
                                    too_old += 1
                                    continue
                                if pub_date > today:
                                    skipped += 1
                                    continue
                                page_has_recent = True
                            else:
                                # Date inconnue → on accepte (conservateur)
                                pub_date = today
                                page_has_recent = True

                            # Pré-filtre heuristique
                            keep, drop_reason = pre_filter_candidate(title, source=source)
                            if not keep:
                                logger.debug("[cnom] pre_filter DROP '%s' (%s)", title[:60], drop_reason)
                                skipped += 1
                                continue

                            raw_payload: dict[str, Any] = {
                                "href": abs_url,
                                "title": title,
                                "section": section_label,
                                "source_url": section_url,
                                "feed_source": source,
                                "scraped_date": str(today),
                            }

                            row = build_candidate_row(
                                source=source,
                                external_id=abs_url,
                                official_url=abs_url,
                                official_date=pub_date,
                                title_raw=title,
                                content_raw=None,
                                raw_payload=raw_payload,
                            )

                            if insert_candidate(cur, row):
                                inserted += 1
                                logger.debug("[cnom] INS '%s'", title[:70])
                            else:
                                deduped += 1

                        # Arrêter la pagination si toute la page est trop vieille
                        if not page_has_recent and items:
                            logger.debug("[cnom] arrêt pagination %s — page trop ancienne", section_label)
                            break

            conn.commit()

    logger.info(
        "[cnom] vu=%d ins=%d dup=%d ign=%d trop_vieux=%d",
        seen, inserted, deduped, skipped, too_old,
    )
    return {
        "seen": seen,
        "inserted": inserted,
        "deduped": deduped,
        "skipped": skipped,
        "too_old": too_old,
    }


# ---------------------------------------------------------------------------
# Scraper ameli.fr/medecin — Assurance Maladie actualités médecins
# ---------------------------------------------------------------------------
# ameli.fr est la source officielle de la CNAM pour les médecins libéraux.
# Les actualités couvrent : convention médicale, honoraires, remboursements,
# CCAM, téléconsultation, FMT/Donum, outils praticiens, nouveaux dispositifs.
#
# Aucun flux RSS public disponible. Scraping du listing statique Drupal.
#
# Structure du listing :
#   <article class="node--type-actualite-nationale">
#     <p class="date-actus">27/04/2026</p>
#     <h2 class="titre-actus"><a href="/medecin/actualites/slug"><span>Titre</span></a></h2>
#     <div class="field_actu_main_category">Prise en charge/Tarif</div>
#     <div class="wrapper-content">...extrait...</div>
#   </article>
#
# Pagination : ?page=0..N (10 articles/page, ~10-12 pages par an)
# source_type : déterminé par LLM (contenu mixte reglementaire/recommandation)
# ---------------------------------------------------------------------------

_AMELI_BASE = "https://www.ameli.fr"
_AMELI_LISTING = f"{_AMELI_BASE}/medecin/actualites"

# Regex date ameli.fr : format dd/mm/yyyy
_AMELI_DATE_RE = re.compile(r"^(\d{2})/(\d{2})/(\d{4})$")


def _parse_ameli_date(text: str) -> date | None:
    """Convertit '27/04/2026' → date(2026, 4, 27). Retourne None si invalide."""
    m = _AMELI_DATE_RE.match(text.strip())
    if not m:
        return None
    day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _ameli_extract_articles(html: str) -> list[tuple[str, str, date | None, str, str]]:
    """
    Extrait les articles d'une page de listing ameli.fr/medecin/actualites.
    Retourne une liste de (url_absolue, titre, date_pub|None, catégorie, extrait).
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    results: list[tuple[str, str, date | None, str, str]] = []

    for article in soup.find_all("article", class_=re.compile(r"node--type-actualite")):
        # Date
        date_el = article.find("p", class_="date-actus")
        pub_date = _parse_ameli_date(date_el.get_text(strip=True)) if date_el else None

        # Titre + URL
        titre_el = article.find("h2", class_="titre-actus")
        if not titre_el:
            continue
        a_el = titre_el.find("a")
        if not a_el or not a_el.get("href"):
            continue
        title = a_el.get_text(strip=True)
        abs_url = _AMELI_BASE + a_el["href"]

        # Catégorie
        cat_el = article.find("div", class_="field_actu_main_category")
        category = cat_el.get_text(strip=True) if cat_el else ""

        # Extrait (résumé court visible sur le listing)
        content_el = article.find("div", class_="wrapper-content")
        snippet = content_el.get_text(strip=True) if content_el else ""
        # Nettoyer l'extrait (supprimer le texte "En savoir plus" ou liens internes)
        snippet = re.sub(r"\s+", " ", snippet).strip()

        if len(title) < 10:
            continue

        results.append((abs_url, title, pub_date, category, snippet))

    return results


def collect_ameli_medecin(days: int = 180, max_pages: int = 20) -> dict[str, Any]:
    """
    Scrape les actualités ameli.fr destinées aux médecins libéraux.
    Insère les articles récents (dans la fenêtre `days`) comme candidates
    avec source='ameli_medecin'.

    La source_type (reglementaire/recommandation) est déterminée par le LLM
    car le contenu est mixte : convention médicale (reglementaire) et outils
    pratiques / guides (recommandation).

    Args:
        days: Fenêtre temporelle en arrière depuis aujourd'hui.
        max_pages: Nombre maximum de pages à parcourir (10 articles/page).

    Returns:
        Dict de stats : seen / inserted / deduped / skipped / too_old.
    """
    source = "ameli_medecin"
    today = date.today()
    cutoff = today - timedelta(days=days)

    seen = inserted = deduped = skipped = too_old = 0

    with httpx.Client(follow_redirects=True, timeout=20, headers=_HEADERS) as client:
        with get_conn() as conn:
            with conn.cursor() as cur:
                for page in range(max_pages):
                    url = _AMELI_LISTING if page == 0 else f"{_AMELI_LISTING}?page={page}"
                    try:
                        resp = client.get(url)
                        resp.raise_for_status()
                    except Exception as e:
                        logger.warning("[ameli_medecin] fetch page %d : %s", page, e)
                        break

                    articles = _ameli_extract_articles(resp.text)
                    if not articles:
                        logger.debug("[ameli_medecin] page %d vide", page)
                        break

                    page_has_recent = False

                    for abs_url, title, pub_date, category, snippet in articles:
                        seen += 1

                        # Filtrer par date
                        if pub_date:
                            if pub_date < cutoff:
                                too_old += 1
                                continue
                            if pub_date > today:
                                skipped += 1
                                continue
                            page_has_recent = True
                        else:
                            pub_date = today
                            page_has_recent = True

                        # Pré-filtre heuristique
                        keep, drop_reason = pre_filter_candidate(title, source=source)
                        if not keep:
                            logger.debug(
                                "[ameli_medecin] pre_filter DROP '%s' (%s)", title[:60], drop_reason
                            )
                            skipped += 1
                            continue

                        raw_payload: dict[str, Any] = {
                            "href": abs_url,
                            "title": title,
                            "category": category,
                            "snippet": snippet[:500],
                            "source_url": _AMELI_LISTING,
                            "feed_source": source,
                            "scraped_date": str(today),
                        }

                        row = build_candidate_row(
                            source=source,
                            external_id=abs_url,
                            official_url=abs_url,
                            official_date=pub_date,
                            title_raw=title,
                            # L'extrait du listing enrichit le contexte LLM
                            content_raw=snippet if snippet else None,
                            raw_payload=raw_payload,
                        )

                        if insert_candidate(cur, row):
                            inserted += 1
                            logger.debug("[ameli_medecin] INS [%s] '%s'", category, title[:70])
                        else:
                            deduped += 1

                    # Arrêter si toute la page est hors fenêtre temporelle
                    if not page_has_recent and articles:
                        logger.debug("[ameli_medecin] arrêt pagination — page %d trop ancienne", page)
                        break

            conn.commit()

    logger.info(
        "[ameli_medecin] vu=%d ins=%d dup=%d ign=%d trop_vieux=%d",
        seen, inserted, deduped, skipped, too_old,
    )
    return {
        "seen": seen,
        "inserted": inserted,
        "deduped": deduped,
        "skipped": skipped,
        "too_old": too_old,
    }


# ---------------------------------------------------------------------------
# CARMF — Caisse Autonome de Retraite des Médecins de France
# ---------------------------------------------------------------------------
# Site PHP minimal, pas de RSS. Le listing est une page HTML statique
# (/page.php?page=actualites/actualites_menu.htm) qui liste les articles
# en cours + un lien d'archive par année passée. Chaque article est une
# page HTML distincte avec la date dans <p class="date">Le DD mois YYYY</p>.
# Volume : ~3-5 articles/an (PSS, cotisations, retraite, ASV).
# ---------------------------------------------------------------------------

_CARMF_BASE          = "https://www.carmf.fr"
_CARMF_LISTING_URL   = f"{_CARMF_BASE}/page.php?page=actualites/actualites_menu.htm"
_CARMF_HEADERS       = {"User-Agent": "Mozilla/5.0 (compatible; MedNewsBot/1.0)"}
_RE_CARMF_DATE       = re.compile(
    r"Le\s+(\d{1,2})\s+(" + "|".join(re.escape(m) for m in _MONTH_FR) + r")\s+(\d{4})",
    re.IGNORECASE,
)


def _parse_carmf_date(text: str) -> date | None:
    m = _RE_CARMF_DATE.search(text)
    if not m:
        return None
    day, month_name, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
    month = _MONTH_FR.get(month_name)
    if not month:
        return None
    try:
        return date(year, month, day)
    except ValueError:
        return None


def collect_carmf(days: int = 180) -> dict[str, Any]:
    """Scrape le site CARMF (cotisations, PSS, retraite, ASV médecins).

    Stratégie : 1) listing page → liens articles récents ;
                2) fetch chaque article → date + contenu.
    """
    cutoff = date.today() - timedelta(days=days)
    source  = "carmf"
    seen = inserted = deduped = skipped = too_old = 0

    with get_conn() as conn:
        # 1. Récupérer la page de listing
        try:
            resp = httpx.get(_CARMF_LISTING_URL, headers=_CARMF_HEADERS, timeout=20, follow_redirects=True)
            resp.raise_for_status()
        except Exception as e:
            logger.error("[carmf] fetch listing failed: %s", e)
            return {"seen": 0, "inserted": 0, "error": str(e)}

        listing_html = resp.text

        # 2. Extraire les liens d'articles (sauf le menu lui-même et les ancres)
        raw_links = re.findall(
            r'href="(/page\.php\?page=actualites(?!/actualites_menu)[^"#]+)"',
            listing_html,
        )
        article_hrefs: list[str] = []
        seen_hrefs: set[str] = set()
        for href in raw_links:
            if href not in seen_hrefs:
                seen_hrefs.add(href)
                article_hrefs.append(href)

        logger.debug("[carmf] %d liens d'articles trouvés", len(article_hrefs))

        for href in article_hrefs:
            url = f"{_CARMF_BASE}{href}"
            seen += 1
            try:
                art = httpx.get(url, headers=_CARMF_HEADERS, timeout=20, follow_redirects=True)
                art.raise_for_status()
            except Exception as e:
                logger.warning("[carmf] fetch article failed: %s — %s", url, e)
                skipped += 1
                continue

            art_html = art.text

            # Date dans <p class="date">Le DD mois YYYY</p>
            art_date = _parse_carmf_date(art_html)
            if art_date is None:
                # Fallback : extraire l'année depuis l'URL (ex: /2026/pss-2026.htm)
                year_m = re.search(r"/(\d{4})/", href)
                if year_m:
                    art_date = date(int(year_m.group(1)), 1, 1)
                else:
                    logger.debug("[carmf] pas de date dans %s — ignoré", href)
                    skipped += 1
                    continue

            if art_date < cutoff:
                too_old += 1
                continue

            # Titre : <h1> dans div#contentphp
            idx_content = art_html.find("id='contentphp'")
            if idx_content < 0:
                idx_content = art_html.find('id="contentphp"')
            zone = art_html[idx_content:idx_content + 3000] if idx_content >= 0 else art_html[:3000]
            title_m = re.search(r"<h1[^>]*>(.*?)</h1>", zone, re.IGNORECASE | re.DOTALL)
            if not title_m:
                logger.debug("[carmf] pas de titre dans %s", href)
                skipped += 1
                continue
            title = re.sub(r"<[^>]+>", "", title_m.group(1)).strip()
            if not title:
                skipped += 1
                continue

            # Contenu : paragraphes dans div#contentphp
            paras = re.findall(r"<p[^>]*>(.*?)</p>", zone, re.IGNORECASE | re.DOTALL)
            content_parts = []
            for p in paras:
                text = re.sub(r"<[^>]+>", " ", p)
                text = re.sub(r"&[a-z]+;", " ", text)
                text = re.sub(r"\s+", " ", text).strip()
                if len(text) > 40 and 'class="date"' not in p:
                    content_parts.append(text)
            content = " ".join(content_parts[:5])

            keep, drop_reason = pre_filter_candidate(title, source=source)
            if not keep:
                logger.debug("[carmf] pre_filter DROP '%s' (%s)", title[:60], drop_reason)
                skipped += 1
                continue

            row = build_candidate_row(
                source=source,
                external_id=url,
                official_url=url,
                official_date=art_date,
                title_raw=title,
                content_raw=content or None,
            )
            with conn.cursor() as cur:
                if insert_candidate(cur, row):
                    inserted += 1
                    logger.debug("[carmf] INS '%s'", title[:70])
                else:
                    deduped += 1
            conn.commit()

    logger.info("[carmf] vu=%d ins=%d dup=%d ign=%d trop_vieux=%d",
                seen, inserted, deduped, skipped, too_old)
    return {"seen": seen, "inserted": inserted, "deduped": deduped,
            "skipped": skipped, "too_old": too_old}


# ---------------------------------------------------------------------------
# CARPIMKO — Caisse de Retraite des auxiliaires médicaux libéraux
# (Infirmiers, Masseurs-Kinésithérapeutes, Pédicures-Podologues,
#  Orthophonistes, Orthoptistes)
# ---------------------------------------------------------------------------
# Site DNN. Pas de RSS. Les actualités récentes figurent toutes sur la page
# d'accueil sous forme de liens /actualites/{slug}. Chaque article contient
# la date dans <time>jeudi DD mois YYYY</time>.
# Volume : ~6-12 articles/an (cotisations, retraite, réforme assiette sociale).
# ---------------------------------------------------------------------------

_CARPIMKO_BASE        = "https://www.carpimko.com"
_CARPIMKO_HOME_URL    = _CARPIMKO_BASE + "/"
_CARPIMKO_HEADERS     = {"User-Agent": "Mozilla/5.0 (compatible; MedNewsBot/1.0)"}
_RE_CARPIMKO_DATE     = re.compile(
    r"<time[^>]*>\s*(?:\w+\s+)?(\d{1,2})\s+(" + "|".join(re.escape(m) for m in _MONTH_FR) + r")\s+(\d{4})\s*</time>",
    re.IGNORECASE,
)


def _parse_carpimko_date(html: str) -> date | None:
    m = _RE_CARPIMKO_DATE.search(html)
    if not m:
        return None
    day, month_name, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
    month = _MONTH_FR.get(month_name)
    if not month:
        return None
    try:
        return date(year, month, day)
    except ValueError:
        return None


def collect_carpimko(days: int = 180) -> dict[str, Any]:
    """Scrape le site CARPIMKO (cotisations, retraite, assiette sociale auxiliaires médicaux).

    Stratégie : 1) page d'accueil → liens /actualites/{slug} ;
                2) fetch chaque article → date + contenu.
    """
    cutoff = date.today() - timedelta(days=days)
    source  = "carpimko"
    seen = inserted = deduped = skipped = too_old = 0

    with get_conn() as conn:
        # 1. Page d'accueil → liens d'articles
        try:
            resp = httpx.get(_CARPIMKO_HOME_URL, headers=_CARPIMKO_HEADERS, timeout=20, follow_redirects=True)
            resp.raise_for_status()
        except Exception as e:
            logger.error("[carpimko] fetch home failed: %s", e)
            return {"seen": 0, "inserted": 0, "error": str(e)}

        home_html = resp.text

        article_urls: list[str] = []
        seen_urls: set[str] = set()
        for href in re.findall(
            r'href=["\'](' + re.escape(_CARPIMKO_BASE) + r'/actualites/[^"\'#?]+)["\']',
            home_html,
        ):
            if href not in seen_urls:
                seen_urls.add(href)
                article_urls.append(href)

        logger.debug("[carpimko] %d liens d'articles trouvés", len(article_urls))

        for url in article_urls:
            seen += 1
            try:
                art = httpx.get(url, headers=_CARPIMKO_HEADERS, timeout=20, follow_redirects=True)
                art.raise_for_status()
            except Exception as e:
                logger.warning("[carpimko] fetch article failed: %s — %s", url, e)
                skipped += 1
                continue

            art_html = art.text

            art_date = _parse_carpimko_date(art_html)
            if art_date is None:
                logger.debug("[carpimko] pas de date dans %s — ignoré", url)
                skipped += 1
                continue

            if art_date < cutoff:
                too_old += 1
                continue

            # Titre
            title_m = re.search(r'<h1[^>]*class="[^"]*detail-title[^"]*"[^>]*>(.*?)</h1>', art_html, re.IGNORECASE | re.DOTALL)
            if not title_m:
                title_m = re.search(r"<h1[^>]*>(.*?)</h1>", art_html, re.IGNORECASE | re.DOTALL)
            if not title_m:
                skipped += 1
                continue
            title = re.sub(r"<[^>]+>", "", title_m.group(1)).strip()
            if not title:
                skipped += 1
                continue

            # Contenu : <div class="blog-detail ...">
            content_m = re.search(r'class="blog-detail[^"]*"[^>]*>(.*?)</div>', art_html, re.IGNORECASE | re.DOTALL)
            content = ""
            if content_m:
                raw = content_m.group(1)
                paras = re.findall(r"<p[^>]*>(.*?)</p>", raw, re.IGNORECASE | re.DOTALL)
                parts = []
                for p in paras:
                    text = re.sub(r"<[^>]+>", " ", p)
                    text = re.sub(r"&[a-z]+;", " ", text)
                    text = re.sub(r"\s+", " ", text).strip()
                    if len(text) > 30:
                        parts.append(text)
                content = " ".join(parts[:5])

            keep, drop_reason = pre_filter_candidate(title, source=source)
            if not keep:
                logger.debug("[carpimko] pre_filter DROP '%s' (%s)", title[:60], drop_reason)
                skipped += 1
                continue

            row = build_candidate_row(
                source=source,
                external_id=url,
                official_url=url,
                official_date=art_date,
                title_raw=title,
                content_raw=content or None,
            )
            with conn.cursor() as cur:
                if insert_candidate(cur, row):
                    inserted += 1
                    logger.debug("[carpimko] INS '%s'", title[:70])
                else:
                    deduped += 1
            conn.commit()

    logger.info("[carpimko] vu=%d ins=%d dup=%d ign=%d trop_vieux=%d",
                seen, inserted, deduped, skipped, too_old)
    return {"seen": seen, "inserted": inserted, "deduped": deduped,
            "skipped": skipped, "too_old": too_old}
