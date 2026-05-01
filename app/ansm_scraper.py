# app/ansm_scraper.py
"""
Enrichissement du contenu ANSM : extraction du texte clinique depuis les pages
d'informations de sécurité et d'actualités ANSM.

Problème de base :
  Les flux RSS ANSM (ansm_securite, ansm_securite_med, ansm_actualites) ne
  contiennent qu'une ligne ("Publié le JJ/MM/AAAA") → content_raw inutilisable
  pour le scoring LLM. Le vrai contenu (produit concerné, niveau de rappel,
  mesures à prendre, populations concernées) est sur la page HTML.

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

# Headings ANSM à extraire en priorité (order matters)
_PRIORITY_HEADING_RE = re.compile(
    r"(?i)(mesures?\s+(prises?|correctives?)|populations?\s+concern[eé]es?|"
    r"personnes?\s+concern[eé]es?|informations?\s+importantes?|"
    r"produit[s]?\s+concern[eé][s]?|motif[s]?|d[eé]cision|"
    r"recommandations?|conduite[\s ]+[àa][\s ]+tenir|contexte|"
    r"niveau\s+de\s+rappel|action[s]?\s+[àa]\s+mener)"
)


def _fetch_html(url: str, timeout: int = 20) -> str | None:
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.text
    except Exception as e:
        logger.warning("ANSM scraper fetch failed %s : %s", url, e)
        return None


def scrape_ansm_page(url: str) -> dict[str, Any]:
    """
    Scrape une page ANSM et extrait le contenu clinique principal.

    Retourne :
      {
        "content": str | None,   # texte principal extrait (jusqu'à 3000 chars)
        "alert_type": str | None, # type d'alerte détecté dans les métadonnées
      }
    """
    result: dict[str, Any] = {"content": None, "alert_type": None}

    html = _fetch_html(url)
    if not html:
        return result

    soup = BeautifulSoup(html, "html.parser")

    # Supprime les éléments de navigation, pied de page, cookies
    for tag in soup.find_all(["nav", "footer", "header", "script", "style", "aside"]):
        tag.decompose()

    # Cherche la zone de contenu principal
    main = (
        soup.find("main")
        or soup.find("div", {"id": re.compile(r"(?i)content|main|article")})
        or soup.find("div", {"class": re.compile(r"(?i)content|article|page-content|main")})
        or soup.body
    )
    if not main:
        return result

    parts: list[str] = []

    # --- Niveau de rappel / type d'alerte ---
    level_el = main.find(string=re.compile(r"(?i)niveau\s+de\s+rappel"))
    if level_el:
        parent_text = level_el.find_parent().get_text(" ", strip=True) if level_el.find_parent() else ""
        if parent_text and len(parent_text) < 300:
            result["alert_type"] = parent_text
            parts.append(parent_text)

    # --- Sections prioritaires (titre + paragraphes suivants) ---
    for heading in main.find_all(["h2", "h3", "h4"]):
        if not _PRIORITY_HEADING_RE.search(heading.get_text()):
            continue
        section_text = heading.get_text(" ", strip=True)
        sibling = heading.find_next_sibling()
        while sibling and sibling.name not in ("h2", "h3", "h4"):
            t = sibling.get_text(" ", strip=True)
            if t and len(t) > 20:
                section_text += " " + t
            sibling = sibling.find_next_sibling()
        if len(section_text) > 30:
            parts.append(section_text[:800])

    # --- Fallback : tous les paragraphes substantiels ---
    if not parts:
        for p in main.find_all(["p", "li"]):
            t = p.get_text(" ", strip=True)
            if len(t) > 40:
                parts.append(t)

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

    logger.info(
        "ANSM scraper OK %s | contenu=%d chars",
        url,
        len(content) if content else 0,
    )
    return result


def build_ansm_enriched_content(rss_summary: str | None, scraped: dict[str, Any]) -> str | None:
    """
    Fusionne le résumé RSS (souvent une ligne) avec le contenu scrapé ANSM.
    """
    parts: list[str] = []

    if scraped.get("content"):
        parts.append(scraped["content"])

    if rss_summary and rss_summary not in (p[:len(rss_summary)] for p in parts):
        parts.append(f"[RSS] {rss_summary}")

    return "\n\n".join(parts)[:3500] if parts else rss_summary
