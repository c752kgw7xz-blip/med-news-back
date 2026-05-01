# app/carmf_scraper.py
"""
Scraper CARMF — Caisse autonome de retraite des médecins de France.

Le site carmf.fr est un site PHP statique sans flux RSS.
Ce module scrape la page menu actualités puis chaque article individuel.

Structure du site :
  Menu  : https://www.carmf.fr/page.php?page=actualites/actualites_menu.htm
  Articles : /page.php?page=actualites/{categorie}/{annee}/{slug}.htm
  Contenu  : dans la page après le marqueur "Partager", avec date "Le DD mois YYYY"

Appelé depuis rss_collector.py via collect_carmf().
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from datetime import date, datetime, timedelta
from typing import Any

import httpx
import psycopg2
from psycopg2.extras import Json

logger = logging.getLogger(__name__)

BASE_URL = "https://www.carmf.fr"
MENU_URL = f"{BASE_URL}/page.php?page=actualites/actualites_menu.htm"

_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9",
}

_MOIS_FR = {
    "janvier": 1, "février": 2, "mars": 3, "avril": 4,
    "mai": 5, "juin": 6, "juillet": 7, "août": 8,
    "septembre": 9, "octobre": 10, "novembre": 11, "décembre": 12,
}

# Catégories à collecter (divers = souvent technique/administratif, moins utile)
_CATEGORIES = {"communiques", "juridique", "divers"}


def _fetch(url: str, timeout: int = 15) -> str | None:
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.text
    except Exception as e:
        logger.warning("CARMF fetch failed %s : %s", url, e)
        return None


def _clean_html(html_fragment: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html_fragment)
    text = re.sub(r"&[a-z]+;", lambda m: {
        "&amp;": "&", "&lt;": "<", "&gt;": ">", "&nbsp;": " ",
        "&eacute;": "é", "&egrave;": "è", "&ecirc;": "ê",
        "&agrave;": "à", "&acirc;": "â", "&ugrave;": "ù",
        "&ocirc;": "ô", "&iuml;": "ï", "&ucirc;": "û",
        "&oelig;": "œ", "&laquo;": "«", "&raquo;": "»",
    }.get(m.group(0), m.group(0)), text)
    return re.sub(r"\s+", " ", text).strip()


def _parse_date_fr(text: str) -> date | None:
    """Parse 'Le 15 janvier 2026' ou 'Paris, le 29 janvier 2026'."""
    m = re.search(
        r"(?:le\s+)?(\d{1,2})\s+(janvier|f[eé]vrier|mars|avril|mai|juin|juillet|ao[uû]t"
        r"|septembre|octobre|novembre|d[eé]cembre)\s+(\d{4})",
        text, re.IGNORECASE,
    )
    if not m:
        return None
    day, month_str, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
    # Normaliser les variantes accentuées
    month_str = month_str.replace("é", "e").replace("è", "e").replace("û", "u").replace("ô", "o")
    month_num = _MOIS_FR.get(m.group(2).lower()) or _MOIS_FR.get(month_str)
    if not month_num:
        return None
    try:
        return date(year, month_num, day)
    except ValueError:
        return None


def _scrape_article(path: str) -> dict[str, Any] | None:
    """
    Scrape un article CARMF.
    path : chemin relatif, ex '/page.php?page=actualites/communiques/2026/rnai.htm'
    Retourne {title, content, article_date, url} ou None.
    """
    url = BASE_URL + path
    html = _fetch(url)
    if not html:
        return None

    # Contenu après le marqueur "Partager"
    idx = html.find("Partager")
    if idx < 0:
        return None
    fragment = html[idx: idx + 4000]

    text = _clean_html(fragment)

    # Extraire la date
    article_date = _parse_date_fr(text)

    # Extraire le titre : première ligne substantielle après la date
    # Le format est "Partager [lieu,] le DD mois YYYY [type] Titre Corps..."
    # On retire le préfixe date/type pour isoler le titre
    title_text = re.sub(
        r"^Partager\s*(Paris,?\s*)?le\s+\d{1,2}\s+\w+\s+\d{4}\s*"
        r"(Communiqué de presse|Juridique|Information\s+\w+)?\s*",
        "", text, flags=re.IGNORECASE,
    ).strip()
    # Première phrase = titre (jusqu'au premier point ou jusqu'à 120 chars)
    title_end = title_text.find("\n")
    if title_end < 0 or title_end > 120:
        title_end = 120
    title = title_text[:title_end].strip().rstrip(".")

    # Corps = reste du texte (max 3000 chars)
    content = title_text[:3000]

    return {"title": title, "content": content, "article_date": article_date, "url": url}


def _list_article_paths(since: date) -> list[str]:
    """Retourne les chemins d'articles publiés depuis `since`."""
    html = _fetch(MENU_URL)
    if not html:
        return []

    # Extraire tous les liens /page.php?page=actualites/{cat}/{year}/...
    links = re.findall(
        r'href="(/page\.php\?page=actualites/([^/"]+)/(\d{4})/[^"]+\.htm)"',
        html,
    )

    paths = []
    for path, category, year_str in links:
        if category not in _CATEGORIES:
            continue
        year = int(year_str)
        # Filtre rapide sur l'année (évite de scraper des articles de 2012)
        if year < since.year:
            continue
        if path not in paths:
            paths.append(path)

    return paths


def collect_carmf(days: int = 120) -> dict[str, int]:
    """
    Collecte les articles CARMF des `days` derniers jours et les insère en candidates.
    Retourne {"seen": N, "inserted": N, "deduped": N, "skipped": N, "error": ...}.
    """
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise AssertionError("DATABASE_URL is missing in environment.")

    since = date.today() - timedelta(days=days)
    paths = _list_article_paths(since)

    stats = {"seen": 0, "inserted": 0, "deduped": 0, "skipped": 0}

    try:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()

        for path in paths:
            stats["seen"] += 1
            article = _scrape_article(path)
            if not article:
                stats["skipped"] += 1
                continue

            article_date = article["article_date"]
            # Filtre date : ignorer les articles hors fenêtre
            if article_date and article_date < since:
                stats["skipped"] += 1
                continue

            content = article["content"] or ""
            dedupe_key = hashlib.sha256(article["url"].encode()).hexdigest()

            # Vérifier doublon
            cur.execute(
                "SELECT id FROM candidates WHERE dedupe_key = %s", (dedupe_key,)
            )
            if cur.fetchone():
                stats["deduped"] += 1
                continue

            cand_id = str(uuid.uuid4())
            raw_payload = Json({
                "source": "carmf",
                "url": article["url"],
                "title": article["title"],
                "scraped_date": str(article_date) if article_date else None,
            })
            raw_sha256 = hashlib.sha256(content.encode()).hexdigest()
            cur.execute(
                """
                INSERT INTO candidates
                  (id, source, title_raw, content_raw, official_url, official_date,
                   raw_json, raw_sha256, dedupe_key, status, created_at)
                VALUES (%s, 'carmf', %s, %s, %s, %s, %s, %s, %s, 'NEW', NOW())
                ON CONFLICT (dedupe_key) DO NOTHING
                """,
                (
                    cand_id,
                    article["title"][:500],
                    content[:3000],
                    article["url"],
                    article_date,
                    raw_payload,
                    raw_sha256,
                    dedupe_key,
                ),
            )
            if cur.rowcount:
                stats["inserted"] += 1
            else:
                stats["deduped"] += 1

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        logger.error("CARMF collect error: %s", e)
        stats["error"] = str(e)

    return stats
