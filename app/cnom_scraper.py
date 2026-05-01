# app/cnom_scraper.py
"""
Enrichissement du contenu CNOM : extraction du corps de l'article depuis les pages
du Conseil National de l'Ordre des Médecins.

Problème de base :
  Le flux RSS CNOM ne contient que le titre + l'URL — aucun corps de texte.
  Le contenu réel (argumentaire, données, mesures) est dans la page HTML,
  dans le div.node-page__content qui est commun à toutes les sections du site.

Ce module est appelé depuis collect_feed() pour enrichir content_raw avant
insertion en base.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9",
}

# Éléments de bruit à supprimer avant extraction
_NOISE_TAGS = ["nav", "footer", "header", "script", "style", "aside", "form"]

# Sélecteurs CSS candidats pour le contenu principal CNOM
# (dans l'ordre de priorité)
_CONTENT_SELECTORS = [
    ("div", {"class": "node-page__content"}),
    ("div", {"class": re.compile(r"node-page")}),
    ("article", {}),
    ("main", {}),
]


def _fetch_html(url: str, timeout: int = 20) -> str | None:
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.text
    except Exception as e:
        logger.warning("CNOM scraper fetch failed %s : %s", url, e)
        return None


def scrape_cnom_page(url: str) -> dict[str, Any]:
    """
    Scrape une page CNOM et extrait le corps de l'article.

    Retourne :
      {
        "content": str | None,  # texte extrait (jusqu'à 3000 chars)
        "chars":   int,         # longueur du contenu extrait
      }
    """
    result: dict[str, Any] = {"content": None, "chars": 0}

    html = _fetch_html(url)
    if not html:
        return result

    soup = BeautifulSoup(html, "html.parser")

    # Supprime bruit structurel
    for tag in soup.find_all(_NOISE_TAGS):
        tag.decompose()

    # Cherche le conteneur principal
    content_el = None
    for tag_name, attrs in _CONTENT_SELECTORS:
        content_el = soup.find(tag_name, attrs) if attrs else soup.find(tag_name)
        if content_el and len(content_el.get_text(strip=True)) > 100:
            break

    if not content_el:
        logger.debug("CNOM scraper: aucun conteneur trouvé pour %s", url)
        return result

    # Collecte paragraphes substantiels
    parts: list[str] = []
    for el in content_el.find_all(["p", "li", "h2", "h3", "h4", "blockquote"]):
        t = el.get_text(" ", strip=True)
        if len(t) > 30:
            parts.append(t)

    # Fallback : texte brut si aucun <p>/<li> trouvé
    if not parts:
        raw = content_el.get_text(" ", strip=True)
        if raw:
            parts = [raw]

    # Déduplique en préservant l'ordre
    seen: set[str] = set()
    deduped: list[str] = []
    for p in parts:
        key = p[:80]
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    content = "\n\n".join(deduped)[:3000] or None
    result["content"] = content
    result["chars"] = len(content) if content else 0

    logger.info("CNOM scraper OK %s | %d chars", url, result["chars"])
    return result


def build_cnom_enriched_content(rss_summary: str | None, scraped: dict[str, Any]) -> str | None:
    """
    Fusionne le résumé RSS (souvent vide) avec le contenu scrapé CNOM.
    """
    if scraped.get("content"):
        return scraped["content"]
    return rss_summary or None
