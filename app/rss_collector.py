# app/rss_collector.py
"""
Collecteur RSS — 160 feeds actifs, toutes spécialités.

FEEDS = ALL_FEEDS, composé de 5 sections (voir app/sources.py) :
  FR_REGULATORY (15)  : HAS, ANSM, SPF, CNOM, Académie de Médecine…
  FR_SOCIETIES  (27)  : CNGE, SFAR, SFN, SNFGE, AFU, SFORL, SFGG…
  EU_FEEDS      (23)  : EMA, ECDC, ESMO, ERS, EASL, ESICM, EADV…
  JOURNALS      (63)  : NEJM, Lancet, JAMA, Nature Med, BMJ spécialisés…
  CLINICAL_PRESS(32)  : Healio (×14 spés), MedPage, Vascular Specialist…

Enrichissement HAS : les flux HAS ne contiennent que le titre.
  has_rbp, has_ct, has_dm → scraping de la page HTML pour récupérer
  le résumé clinique, les messages clés et le type de document.

Pré-filtres appliqués avant insertion (0 appel LLM) :
  - pre_filter_candidate : élimine nominations, congrès, emploi, etc.
  - NOISY_SOURCES + _passes_jorf_whitelist : filtre supplémentaire
    pour les sources généralistes à haut volume / faible signal.
"""

from __future__ import annotations

import logging
import re
from datetime import date, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn
from app.llm_analysis import pre_filter_candidate, NOISY_SOURCES, _passes_jorf_whitelist
from app.sources import ALL_FEEDS, ALL_PRATIQUE_FEEDS
from app.web_scraper import scrape_all_web
from app.has_scraper import scrape_has_page, build_enriched_content

# Sources HAS dont on enrichit le contenu par scraping de la page.
# has_rbp  → résumé clinique + messages clés (RBP finales)
# has_ct   → SMR/ASMR/indication/population cible (avis médicaments CT)
_HAS_ENRICHABLE_SOURCES = {"has_rbp", "has_ct", "has_dm"}

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flux RSS — définition
# Toutes les URLs ont été vérifiées sur les sites officiels.
# ---------------------------------------------------------------------------

FEEDS: list[dict] = ALL_FEEDS


# ---------------------------------------------------------------------------
# Helpers RSS
# ---------------------------------------------------------------------------

def _parse_entry_date(entry: Any) -> date | None:
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            return date(*entry.published_parsed[:3])
        except Exception:
            pass
    if hasattr(entry, "updated_parsed") and entry.updated_parsed:
        try:
            return date(*entry.updated_parsed[:3])
        except Exception:
            pass
    for attr in ("published", "updated"):
        raw = getattr(entry, attr, None)
        if raw:
            try:
                return parsedate_to_datetime(raw).date()
            except Exception:
                pass
    return None


def _entry_id(entry: Any, feed_url: str) -> str:
    return (
        getattr(entry, "id", None)
        or getattr(entry, "link", None)
        or f"{feed_url}::{getattr(entry, 'title', '')}"
    )


def _entry_url(entry: Any) -> str:
    return getattr(entry, "link", "") or ""


def _entry_title(entry: Any) -> str:
    return (getattr(entry, "title", "") or "").strip()


def _entry_summary(entry: Any) -> str | None:
    summary = getattr(entry, "summary", None) or getattr(entry, "description", None)
    if summary:
        clean = re.sub(r"<[^>]+>", " ", summary)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean[:2000] if clean else None
    return None


_JS_REDIRECT_RE = re.compile(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]")

_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
}


def fetch_feed(feed_url: str, timeout: int = 20) -> feedparser.FeedParserDict | None:
    """
    Récupère un flux RSS.
    Gère les protections anti-bot par redirect JavaScript (ex: HAS) :
    la 1ère requête pose un cookie et retourne un path de redirect en JS ;
    on suit ce path manuellement avec le cookie pour obtenir le vrai RSS.
    """
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS) as client:
            r = client.get(feed_url)
            r.raise_for_status()

            # Détecte un redirect JS (anti-bot) : content-type HTML + window.location.href
            ct = r.headers.get("content-type", "")
            if "html" in ct:
                m = _JS_REDIRECT_RE.search(r.text)
                if m:
                    redirect_path = m.group(1)
                    if redirect_path.startswith("http"):
                        redirect_url = redirect_path
                    else:
                        base = str(r.url).split("/", 3)[:3]  # scheme + host
                        redirect_url = "/".join(base) + redirect_path
                    logger.debug("Fetch RSS %s → redirect JS → %s", feed_url, redirect_url)
                    r = client.get(redirect_url)
                    r.raise_for_status()

            return feedparser.parse(r.text)
    except Exception as e:
        logger.warning("Fetch RSS %s échoué : %s", feed_url, e)
        return None


# ---------------------------------------------------------------------------
# Collecteur d'un flux
# ---------------------------------------------------------------------------

def collect_feed(feed_config: dict, days: int = 35) -> dict[str, int]:
    url    = feed_config["url"]
    source = feed_config["source"]
    today  = date.today()
    start  = today - timedelta(days=days)

    parsed = fetch_feed(url)
    if parsed is None or not hasattr(parsed, "entries"):
        logger.warning("[%s] flux inaccessible", source)
        return {"seen": 0, "inserted": 0, "deduped": 0, "skipped": 0, "error": "fetch_failed"}

    entries = parsed.entries or []
    seen = inserted = deduped = skipped = 0

    with get_conn() as conn:
        with conn.cursor() as cur:
            for entry in entries:
                seen += 1
                title = _entry_title(entry)
                if not title:
                    skipped += 1
                    continue

                pub_date = _parse_entry_date(entry) or today
                if pub_date < start or pub_date > today:
                    skipped += 1
                    continue

                entry_id  = _entry_id(entry, url)
                entry_url = _entry_url(entry)
                summary   = _entry_summary(entry)

                if not entry_url:
                    skipped += 1
                    continue

                # ── Pré-filtre heuristique (0 appel LLM) ─────────────────────
                # 1. Filtre générique : nominations, événements, congrès...
                keep, drop_reason = pre_filter_candidate(title, source=source)
                if not keep:
                    logger.debug("[%s] pre_filter DROP '%s' (%s)", source, title[:60], drop_reason)
                    skipped += 1
                    continue
                # 2. Filtre whitelist médicale pour les sources bruyantes
                if source in NOISY_SOURCES and not _passes_jorf_whitelist(title):
                    logger.debug("[%s] noisy_source DROP '%s'", source, title[:60])
                    skipped += 1
                    continue

                # ── Enrichissement HAS : scraping de la page de recommandation ──
                # Le flux RSS HAS ne contient que le titre. On va chercher le vrai
                # résumé clinique + messages clés directement sur la page HTML.
                enriched_content = summary  # fallback : description RSS (souvent vide)
                if source in _HAS_ENRICHABLE_SOURCES and entry_url:
                    try:
                        scraped = scrape_has_page(entry_url, source=source)
                        # Si la page est finalement un doc de cadrage, on skip
                        if scraped.get("is_scoping_doc"):
                            logger.debug("[%s] has_scraper: scoping_doc DROP '%s'", source, title[:60])
                            skipped += 1
                            continue
                        enriched_content = build_enriched_content(summary, scraped)
                    except Exception as e:
                        logger.warning("[%s] has_scraper error for %s : %s", source, entry_url, e)

                raw_payload = {
                    "id": entry_id,
                    "title": title,
                    "link": entry_url,
                    "summary": enriched_content,
                    "published": str(getattr(entry, "published", "")),
                    "feed_source": source,
                    "feed_label": feed_config.get("label", ""),
                    "audience": feed_config.get("audience", []),
                }

                row = build_candidate_row(
                    source=source,
                    external_id=entry_id,
                    official_url=entry_url,
                    official_date=pub_date,
                    title_raw=title,
                    content_raw=enriched_content,
                    raw_payload=raw_payload,
                )

                if insert_candidate(cur, row):
                    inserted += 1
                else:
                    deduped += 1

        conn.commit()

    logger.info("[%s] vu=%d ins=%d dup=%d ign=%d", source, seen, inserted, deduped, skipped)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ---------------------------------------------------------------------------
# Collecteur global
# ---------------------------------------------------------------------------

def collect_all_rss(days: int = 35) -> dict[str, Any]:
    """
    Lance la collecte de tous les flux RSS actifs.
    Appelé par le scheduler mensuel.
    """
    results = {}
    for feed in FEEDS:
        try:
            results[feed["source"]] = collect_feed(feed, days=days)
        except Exception as e:
            logger.error("[%s] erreur : %s", feed["source"], e)
            results[feed["source"]] = {"error": str(e)}
    return results


# ---------------------------------------------------------------------------
# Collecteurs par source (appelés depuis sources_routes.py)
# ---------------------------------------------------------------------------

def _collect_by_prefix(prefix: str, days: int = 35) -> dict[str, Any]:
    results = {}
    for feed in FEEDS:
        if feed["source"].startswith(prefix):
            try:
                results[feed["source"]] = collect_feed(feed, days=days)
            except Exception as e:
                logger.error("[%s] erreur : %s", feed["source"], e)
                results[feed["source"]] = {"error": str(e)}
    return results


def collect_has(days: int = 35) -> dict[str, Any]:
    return _collect_by_prefix("has", days)


def collect_ansm(days: int = 35) -> dict[str, Any]:
    return _collect_by_prefix("ansm", days)


def collect_spf(days: int = 35) -> dict[str, Any]:
    # Santé publique France est exclu des sources retenues (épidémiologie,
    # pas réglementaire — voir docstring module). Aucun feed n'a source "spf".
    return {"inserted": 0, "skipped": 0, "errors": 0, "note": "source spf non activée"}


def collect_pratique(days: int = 90) -> dict[str, Any]:
    """
    Collecte les sources pratiques médicales :
    - Flux RSS : recommandations, bon usage, sociétés savantes (ALL_PRATIQUE_FEEDS)
    - Scraping HTML : sociétés sans RSS (SFH, SFR, SFO, SFPédiatrie, SOFCOT)

    Par défaut days=90 pour capturer l'historique récent des nouveaux feeds.
    Le scraping HTML n'utilise pas le paramètre days (pas de date dans les pages).
    """
    results: dict[str, Any] = {}

    # ── Flux RSS ─────────────────────────────────────────────────────────
    for feed in ALL_PRATIQUE_FEEDS:
        try:
            results[feed["source"]] = collect_feed(feed, days=days)
        except Exception as e:
            logger.error("[%s] erreur : %s", feed["source"], e)
            results[feed["source"]] = {"error": str(e)}

    # ── Scraping HTML (sociétés sans RSS) ─────────────────────────────────
    web_results = scrape_all_web()
    results.update(web_results)

    return results
