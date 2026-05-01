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
from app.llm_analysis import pre_filter_candidate, NOISY_SOURCES, _passes_jorf_whitelist, passes_bo_social_allowlist
from app.sources import ALL_FEEDS, ALL_PRATIQUE_FEEDS
from app.web_scraper import scrape_all_web
from app.has_scraper import scrape_has_page, build_enriched_content
from app.ansm_scraper import scrape_ansm_page, build_ansm_enriched_content
from app.cnom_scraper import scrape_cnom_page, build_cnom_enriched_content

# Sources HAS dont on enrichit le contenu par scraping de la page.
# has_rbp  → résumé clinique + messages clés (RBP finales)
# has_ct   → SMR/ASMR/indication/population cible (avis médicaments CT)
_HAS_ENRICHABLE_SOURCES = {"has_rbp", "has_ct", "has_dm"}

# Sources ANSM dont le flux RSS ne contient qu'une ligne de date.
# On enrichit en scrapant la page pour récupérer le contenu clinique réel.
_ANSM_ENRICHABLE_SOURCES = {"ansm_securite", "ansm_securite_med", "ansm_actualites"}

# Sources RSS de journaux médicaux dont le flux ne contient que métadonnées.
# Pour chacune, on interroge l'API PubMed par titre pour récupérer l'abstract.
# ScienceDirect bloque les scrapers (403) — PubMed est la seule voie fiable.
_JOURNAL_ENRICHABLE_SOURCES = {"ann_thorac_surg_rss", "jto_rss", "lung_cancer_rss"}

# Sources médecin libéral dont le RSS ne contient que le titre + URL.
# On scrape la page HTML pour récupérer le corps de l'article.
_CNOM_ENRICHABLE_SOURCES = {"cnom"}


def _fetch_pubmed_abstract_by_title(title: str) -> str | None:
    """
    Cherche un article PubMed par titre et retourne son abstract complet.
    Utilisé pour enrichir les RSS de journaux dont le flux ne contient
    que les métadonnées (auteurs, volume, numéro) sans abstract.
    Retourne None si l'article n'est pas encore indexé (délai NLM 2-6 semaines).
    """
    try:
        search = httpx.get(
            "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi",
            params={"db": "pubmed", "term": title[:120], "retmode": "json", "retmax": 1},
            timeout=10,
        )
        ids = search.json().get("esearchresult", {}).get("idlist", [])
        if not ids:
            return None
        fetch = httpx.get(
            "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi",
            params={"db": "pubmed", "id": ids[0], "retmode": "text", "rettype": "abstract"},
            timeout=10,
        )
        text = fetch.text.strip()
        # Garde uniquement si l'abstract est substantiel (pas un éditorial sans abstract)
        if any(kw in text for kw in ("BACKGROUND", "OBJECTIVE", "METHODS", "RESULTS", "INTRODUCTION")):
            return text[:3000]
        return None
    except Exception:
        return None


def _fetch_abstract_crossref_s2(title: str) -> str | None:
    """
    Fallback 1 quand PubMed n'a pas encore indexé l'article (délai NLM 2-6 semaines).
    CrossRef (titre → DOI) → Semantic Scholar (DOI → abstract).
    """
    try:
        r = httpx.get(
            "https://api.crossref.org/works",
            params={"query.title": title[:100], "rows": 1},
            headers={"User-Agent": "MedNewsBot/1.0 (contact@mednews.fr)"},
            timeout=10,
        )
        items = r.json().get("message", {}).get("items", [])
        doi = items[0].get("DOI") if items else None
        if not doi:
            return None
        r2 = httpx.get(
            f"https://api.semanticscholar.org/graph/v1/paper/DOI:{doi}",
            params={"fields": "abstract"},
            timeout=10,
        )
        if r2.status_code != 200:
            return None
        abstract = r2.json().get("abstract")
        if abstract and len(abstract) > 100:
            return abstract[:3000]
        return None
    except Exception:
        return None


def _fetch_abstract_openalex(title: str) -> str | None:
    """
    Fallback 2 : OpenAlex (~250M articles, bonne couverture articles récents).
    L'abstract est stocké sous forme d'index inversé — on le reconstruit.
    """
    try:
        r = httpx.get(
            "https://api.openalex.org/works",
            params={"search": title[:100], "per-page": 1, "select": "abstract_inverted_index"},
            headers={"User-Agent": "MedNewsBot/1.0 (contact@mednews.fr)"},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        results = r.json().get("results", [])
        if not results:
            return None
        inv = results[0].get("abstract_inverted_index")
        if not inv:
            return None
        words = sorted([(pos, word) for word, positions in inv.items() for pos in positions])
        abstract = " ".join(w for _, w in words)
        if abstract and len(abstract) > 100:
            return abstract[:3000]
        return None
    except Exception:
        return None

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

def collect_feed(feed_config: dict, days: int = 120) -> dict[str, int]:
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
                # 3. bo_social : allowlist positive — garder uniquement
                #    instructions/circulaires/notes DGS/DSS/DGOS/DREES
                if source == "bo_social" and not passes_bo_social_allowlist(title):
                    logger.debug("[bo_social] allowlist DROP '%s'", title[:60])
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

                # ── Enrichissement ANSM : scraping de la page de l'alerte ───
                # Les flux RSS ANSM ne contiennent qu'une ligne de date.
                # On va chercher le vrai contenu (mesures, produits, population)
                # directement sur la page HTML pour que le LLM puisse scorer.
                if source in _ANSM_ENRICHABLE_SOURCES and entry_url:
                    try:
                        scraped_ansm = scrape_ansm_page(entry_url)
                        enriched_content = build_ansm_enriched_content(enriched_content, scraped_ansm)
                    except Exception as e:
                        logger.warning("[%s] ansm_scraper error for %s : %s", source, entry_url, e)

                # ── Enrichissement CNOM : scraping de la page de l'article ──
                # Le flux RSS CNOM ne contient que le titre + URL, sans corps.
                # On scrape la page HTML (div.node-page__content) pour avoir
                # le texte complet et permettre un scoring LLM pertinent.
                if source in _CNOM_ENRICHABLE_SOURCES and entry_url:
                    try:
                        scraped_cnom = scrape_cnom_page(entry_url)
                        enriched_content = build_cnom_enriched_content(enriched_content, scraped_cnom)
                    except Exception as e:
                        logger.warning("[%s] cnom_scraper error for %s : %s", source, entry_url, e)

                # ── Enrichissement journaux : lookup PubMed par titre ────────
                # Les flux RSS ScienceDirect (Ann Thorac Surg, JTO, Lung Cancer)
                # ne contiennent que les métadonnées. On interroge l'API eutils
                # PubMed pour retrouver l'abstract complet. Articles non encore
                # indexés (délai NLM 2-6 semaines) restent avec métadonnées seules.
                if source in _JOURNAL_ENRICHABLE_SOURCES:
                    abstract = _fetch_pubmed_abstract_by_title(title)
                    if abstract:
                        enriched_content = abstract
                        logger.debug("[%s] pubmed_abstract OK '%s'", source, title[:60])
                    else:
                        abstract = _fetch_abstract_crossref_s2(title)
                        if abstract:
                            enriched_content = abstract
                            logger.debug("[%s] crossref_s2 OK '%s'", source, title[:60])
                        else:
                            abstract = _fetch_abstract_openalex(title)
                            if abstract:
                                enriched_content = abstract
                                logger.debug("[%s] openalex OK '%s'", source, title[:60])
                            else:
                                logger.debug("[%s] abstract non trouvé '%s'", source, title[:60])

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

def collect_all_rss(days: int = 120) -> dict[str, Any]:
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

def _collect_by_prefix(prefix: str, days: int = 120) -> dict[str, Any]:
    results = {}
    for feed in FEEDS:
        if feed["source"].startswith(prefix):
            try:
                results[feed["source"]] = collect_feed(feed, days=days)
            except Exception as e:
                logger.error("[%s] erreur : %s", feed["source"], e)
                results[feed["source"]] = {"error": str(e)}
    return results


def collect_has(days: int = 120) -> dict[str, Any]:
    return _collect_by_prefix("has", days)


def collect_ansm(days: int = 120) -> dict[str, Any]:
    return _collect_by_prefix("ansm", days)


def collect_spf(days: int = 120) -> dict[str, Any]:
    # Santé publique France est exclu des sources retenues (épidémiologie,
    # pas réglementaire — voir docstring module). Aucun feed n'a source "spf".
    return {"inserted": 0, "skipped": 0, "errors": 0, "note": "source spf non activée"}


def collect_pratique(days: int = 120) -> dict[str, Any]:
    """
    Collecte les sources pratiques médicales :
    - Flux RSS : recommandations, bon usage, sociétés savantes (ALL_PRATIQUE_FEEDS)
    - Scraping HTML : sociétés sans RSS (SFH, SFR, SFO, SFPédiatrie, SOFCOT)

    Par défaut days=120 pour capturer l'historique récent des nouveaux feeds.
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
