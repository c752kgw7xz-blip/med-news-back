# app/web_scraper.py
"""
Collecteur HTML — sociétés savantes sans flux RSS.

Stratégie : scrape la page "publications/recommandations" de chaque société,
extrait les liens vers des documents récents, insère en base via le même
pipeline que le collecteur RSS.

Utilisé pour couvrir les spécialités importantes dont le site ne propose pas
de flux RSS (SFH hématologie, SFR radiologie, SFO ophtalmologie, SFPédiatrie,
SOFCOT orthopédie) — voir STRATEGY_NO_RSS dans sources_pratique.py.

Volume attendu : 2-10 documents/an par société → collecte trimestrielle suffit.
Les recommandations de ces sociétés passent aussi partiellement par has_rbp
(HAS valide la plupart des guidelines nationales), donc la couverture est
partiellement assurée même sans ce scraper.
"""

from __future__ import annotations

import logging
import re
from datetime import date
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

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
    # Section publications/rapports : rapports annuels de recommandations.
    # Volume : ~1-3 rapports/an + actualités ANSM liées à l'ophtalmologie.
    {
        "url": "https://www.sfo-online.fr/publications/rapports",
        "source": "sfo",
        "label": "SFO — Rapports et recommandations ophtalmologie",
        "source_type": "recommandation",
        "audience": ["medecins"],
        "specialty_hint": "ophtalmologie",
        "link_pattern": r"sfo-online\.fr/publications",
        "exclude_pattern": r"/(agenda|annuaire|adhesion|contacts|jfo$|fiches-informations-aux-medecins)(/|$)",
    },

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

                raw_payload: dict[str, Any] = {
                    "href": href,
                    "title": title,
                    "source_url": url,
                    "feed_source": source,
                    "feed_label": label,
                    "audience": config.get("audience", []),
                    "scraped_date": str(today),
                }

                row = build_candidate_row(
                    source=source,
                    external_id=href,           # URL = identifiant stable
                    official_url=href,
                    official_date=today,        # pas de date publiée → aujourd'hui
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
    Volume faible → pas de parallélisme nécessaire.
    """
    targets = sources or WEB_SCRAPER_SOURCES
    results: dict[str, Any] = {}
    for config in targets:
        try:
            results[config["source"]] = scrape_source(config)
        except Exception as e:
            logger.error("[%s] erreur : %s", config["source"], e)
            results[config["source"]] = {"error": str(e)}
    return results
