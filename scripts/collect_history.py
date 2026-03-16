#!/usr/bin/env python3
"""
Collecte rétroactive depuis DATE_DEBUT jusqu'à aujourd'hui.

Sources :
  1. JORF     — PISTE API, filtre DATE_PUBLICATION, toutes les pages
  2. HAS      — RSS (feed complet, 50 items, couvre depuis jan 2026)
  3. ANSM     — Scraping listing + pagination (?page=N)
  4. BO Social — Scraping pages sectorielles (bo-sante + bo-travail, ?page=N)

Ne lance PAS l'analyse LLM.
Insère les candidats bruts (status = NEW) avec déduplication (ON CONFLICT DO NOTHING).
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import date, datetime
from typing import Any

# ── Projet dans le path ────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import httpx
import feedparser

from app.db import get_conn
from app.collector_utils import build_candidate_row, insert_candidate
from app.piste_client import piste_post
from app.rss_collector import (
    FEEDS, fetch_feed, _parse_entry_date,
    _entry_title, _entry_url, _entry_id, _entry_summary,
)

# ── Constantes ────────────────────────────────────────────────────────────────
DATE_DEBUT: date = date(2026, 1, 1)
DATE_FIN:   date = date.today()

# Mots-clés médicaux pour le JORF (utilisés comme filtre d'inclusion titre/nature)
# Permet de ne garder que les textes pertinents pour les professionnels de santé.
MEDICAL_KEYWORDS = [
    # Existants (métiers)
    "médecin", "pharmacien", "infirmier", "sage-femme", "dentiste",
    "biologiste", "radiologue", "kinésithérapeute", "praticien",
    # Existants (actes / tarifs)
    "prescription", "honoraires", "tarif", "remboursement", "cotation",
    "ccam", "ngap", "acte médical",
    # Existants (système)
    "assurance maladie", "conventionné", "convention nationale", "avenant",
    # Nouveaux (pratique)
    "télémédecine", "ordonnance", "certificat", "urgences", "garde",
    # Nouveaux (établissements / spécialités)
    "hôpital", "clinique", "établissement de santé", "ars",
    # Codes
    "code de la santé", "code de la sécurité sociale",
]

# Natures JORF à conserver (filtre conservateur, inclusif)
KEEP_NATURE_JORF = {"ARRETE", "DECRET", "LOI", "ORDONNANCE"}
DROP_TITLE_CONTAINS = [
    "avis de vacance",
    "documents déposés",
    "résultats",
    "cote & score",
]

_JS_REDIRECT_RE = re.compile(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]")
_HEADERS_BOT = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}
_HEADERS_BROWSER = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _pdate(v: Any) -> date | None:
    """Parse date ISO depuis une chaîne PISTE (YYYY-MM-DDTxx ou YYYY-MM-DD)."""
    if not isinstance(v, str) or len(v) < 10:
        return None
    try:
        return date.fromisoformat(v[:10])
    except ValueError:
        return None


def _extract_items(data: Any) -> list[dict]:
    if isinstance(data, dict):
        for key in ("results", "list", "hits", "data"):
            v = data.get(key)
            if isinstance(v, list) and v:
                return v
    if isinstance(data, list):
        return data
    return []


def _keep_jorf(nature: Any, title: Any) -> bool:
    n = (nature or "").strip()
    t = (title or "").strip().lower()
    if n not in KEEP_NATURE_JORF:
        return False
    return not any(bad in t for bad in DROP_TITLE_CONTAINS)


def _get_http(url: str, timeout: int = 30, follow_redirect_js: bool = False) -> httpx.Response | None:
    """GET simple avec gestion optionnelle du redirect JS (anti-bot HAS)."""
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS_BROWSER) as client:
            r = client.get(url)
            if follow_redirect_js and "html" in r.headers.get("content-type", ""):
                m = _JS_REDIRECT_RE.search(r.text)
                if m:
                    base = str(r.url).rsplit("/", maxsplit=1)[0].rsplit("/", maxsplit=1)[0]
                    base = "/".join(str(r.url).split("/")[:3])
                    r = client.get(base + m.group(1))
            return r
    except Exception as e:
        print(f"  [GET] {url} → ERREUR: {e}")
        return None


def _insert_bulk(rows: list[dict]) -> tuple[int, int]:
    """Insère une liste de CandidateRow en base. Retourne (inserted, deduped)."""
    ins = dup = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in rows:
                if insert_candidate(cur, row):
                    ins += 1
                else:
                    dup += 1
        conn.commit()
    return ins, dup


# ── 1. JORF ───────────────────────────────────────────────────────────────────

def collect_jorf_history(date_debut: date, date_fin: date) -> dict:
    """
    Collecte JORF via l'API PISTE.
    Filtre : DATE_PUBLICATION dans [date_debut, date_fin], nature ARRETE/DECRET/LOI/ORDONNANCE.
    Pagine jusqu'à épuisement (totalResultNumber).
    """
    source = "legifrance_jorf"
    page_size = 50
    seen = inserted = deduped = skipped = page = 0
    total_api = None

    rows: list[dict] = []

    print(f"  JORF : collecte du {date_debut} au {date_fin}…")

    while True:
        page += 1
        payload = {
            "fond": "JORF",
            "recherche": {
                "pageNumber": page,
                "pageSize": page_size,
                "operateur": "ET",
                "typePagination": "DEFAUT",
                "filtres": [{
                    "facette": "DATE_PUBLICATION",
                    "dates": {
                        "start": date_debut.strftime("%Y-%m-%dT00:00:00.000+0000"),
                        "end":   date_fin.strftime("%Y-%m-%dT23:59:59.000+0000"),
                    },
                }],
            },
        }
        try:
            data = piste_post("/search", payload)
        except Exception as e:
            print(f"  JORF page {page} ERREUR: {e}")
            break

        if total_api is None:
            total_api = data.get("totalResultNumber", 0)
            pages_total = -(-total_api // page_size)  # ceil
            print(f"  JORF : {total_api} résultats API → ~{pages_total} pages")

        items = _extract_items(data)
        if not items:
            break

        for it in items:
            if not isinstance(it, dict):
                continue
            seen += 1

            titles = it.get("titles") if isinstance(it.get("titles"), list) else []
            t0 = titles[0] if titles and isinstance(titles[0], dict) else {}
            jorftext_id = t0.get("cid")
            title = t0.get("title")
            nature = it.get("nature") or it.get("type")

            if not _keep_jorf(nature, title):
                skipped += 1
                continue

            pub_d = _pdate(it.get("datePublication")) or _pdate(it.get("date"))
            if not pub_d or not (date_debut <= pub_d <= date_fin):
                skipped += 1
                continue

            if not (isinstance(jorftext_id, str) and jorftext_id.startswith("JORFTEXT")):
                skipped += 1
                continue

            rows.append(build_candidate_row(
                source=source,
                external_id=jorftext_id,
                official_url=f"https://www.legifrance.gouv.fr/jorf/id/{jorftext_id}",
                official_date=pub_d,
                title_raw=(title or "").strip() or "(no title)",
                jorftext_id=jorftext_id,
                raw_payload=it,
            ))

        if total_api and page * page_size >= total_api:
            break

        time.sleep(0.3)  # politesse API

    inserted, deduped = _insert_bulk(rows)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ── 2. HAS (RSS) ──────────────────────────────────────────────────────────────

def collect_has_history(date_debut: date, date_fin: date) -> dict:
    """
    Collecte HAS via le flux RSS (50 items, bypass anti-bot JS intégré dans fetch_feed).
    Le flux HAS couvre les publications depuis 2018 → suffit pour 2026.
    """
    feed_cfg = next(f for f in FEEDS if f["source"] == "has_rbp")
    source = "has_rbp"
    seen = inserted = deduped = skipped = 0

    print(f"  HAS : collecte RSS du {date_debut} au {date_fin}…")

    parsed = fetch_feed(feed_cfg["url"])
    if parsed is None:
        return {"seen": 0, "inserted": 0, "deduped": 0, "skipped": 0, "error": "fetch_failed"}

    rows: list[dict] = []

    for entry in (parsed.entries or []):
        seen += 1
        title = _entry_title(entry)
        url   = _entry_url(entry)
        if not title or not url:
            skipped += 1
            continue

        pub_date = _parse_entry_date(entry) or date_fin
        if not (date_debut <= pub_date <= date_fin):
            skipped += 1
            continue

        entry_id = _entry_id(entry, feed_cfg["url"])
        summary  = _entry_summary(entry)

        rows.append(build_candidate_row(
            source=source,
            external_id=entry_id,
            official_url=url,
            official_date=pub_date,
            title_raw=title,
            content_raw=summary,
            raw_payload={
                "id": entry_id, "title": title, "link": url,
                "summary": summary, "published": str(getattr(entry, "published", "")),
                "feed_source": source,
            },
        ))

    inserted, deduped = _insert_bulk(rows)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ── 3. ANSM (scraping listing) ────────────────────────────────────────────────

_ANSM_BASE = "https://ansm.sante.fr"

_ANSM_ARTICLE_RE = re.compile(
    r'<a\s+href="(/informations-de-securite/[^"]+)"\s+title="([^"]+)"',
    re.DOTALL,
)
_ANSM_DATE_RE = re.compile(
    r'PUBLIÉ LE\s+(\d{2}/\d{2}/\d{4})',
)
_ANSM_DISPO_DATE_RE = re.compile(
    r'datetime="(\d{4}-\d{2}-\d{2})',
)

_ANSM_LISTING_FEEDS = [
    "/informations-de-securite/",
    # Note : /disponibilites-des-produits-de-sante/ redirige vers /medicaments
    # dont la structure HTML n'a pas de <article class="article-item">
    # → non supporté pour l'instant
]


def _parse_ansm_page(html: str) -> list[tuple[str, str, str | None]]:
    """
    Extrait (path, title, date_str) d'une page de listing ANSM.
    date_str format: DD/MM/YYYY ou None.
    """
    results = []
    # Split par article card
    blocks = html.split('<article class="article-item')
    for block in blocks[1:]:
        # Link + title
        m_link = re.search(r'href="(/[^"]+)"\s+title="([^"]+)"', block)
        if not m_link:
            continue
        path  = m_link.group(1)
        title = m_link.group(2).strip()

        # Date
        m_date = _ANSM_DATE_RE.search(block)
        date_str = m_date.group(1) if m_date else None

        results.append((path, title, date_str))
    return results


def _parse_date_fr(date_str: str | None) -> date | None:
    """Parse DD/MM/YYYY."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%d/%m/%Y").date()
    except ValueError:
        return None


def collect_ansm_history(date_debut: date, date_fin: date) -> dict:
    """
    Collecte ANSM par scraping de la page de listing.
    Pagine via ?page=N jusqu'à atteindre date_debut.
    Source : ansm.sante.fr/informations-de-securite/ (sécurité médicaments/DM)
    """
    source = "ansm_securite"
    seen = inserted = deduped = skipped = 0

    print(f"  ANSM : scraping listing du {date_debut} au {date_fin}…")

    rows: list[dict] = []
    seen_paths: set[str] = set()

    for listing_path in _ANSM_LISTING_FEEDS:
        page = 1
        listing_source = "ansm_securite" if "securite" in listing_path else "ansm_ruptures"

        while True:
            url = f"{_ANSM_BASE}{listing_path}?page={page}"
            r = _get_http(url)
            if not r or r.status_code != 200:
                break

            articles = _parse_ansm_page(r.text)
            if not articles:
                break

            in_range_count = 0
            for path, title, date_str in articles:
                seen += 1
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                pub_date = _parse_date_fr(date_str)
                if pub_date is None:
                    skipped += 1
                    continue

                if pub_date > date_fin:
                    skipped += 1
                    continue

                if pub_date < date_debut:
                    skipped += 1
                    continue

                in_range_count += 1
                full_url = _ANSM_BASE + path
                rows.append(build_candidate_row(
                    source=listing_source,
                    external_id=path,
                    official_url=full_url,
                    official_date=pub_date,
                    title_raw=title,
                    raw_payload={"path": path, "title": title, "date": date_str, "source": listing_source},
                ))

            # Stop si toute la page est hors plage (ANSM trié desc mais pas strictement)
            dates_on_page = [_parse_date_fr(d) for _, _, d in articles if d]
            oldest_on_page = min((d for d in dates_on_page if d), default=None)
            if oldest_on_page and oldest_on_page < date_debut and in_range_count == 0:
                break

            page += 1
            time.sleep(0.2)

    inserted, deduped = _insert_bulk(rows)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ── 4. BO Social (scraping listing sectoriel) ─────────────────────────────────

_BO_BASE = "https://bulletins-officiels.social.gouv.fr"

_BO_SECTIONS = [
    "bo-sante-protection-sociale-solidarites",
    "bo-travail-emploi-formation-professionnelle",
]

_BO_SORT_PARAMS = "?sort_by=field_ref_modification_date_value&sort_order=DESC"


def _parse_bo_page(html: str) -> list[tuple[str, str, date | None]]:
    """
    Extrait (path, title, pub_date) depuis une page de listing BO Social.
    Structure : div about="/path" data-component-id="dsfr4drupal:card"
    """
    results = []
    # Le div a la forme : <div about="/path" data-component-id="dsfr4drupal:card" ...>
    # On splitte sur l'attribut unique (sans le préfixe <div> car about= vient avant)
    blocks = html.split('data-component-id="dsfr4drupal:card"')
    for block in blocks[1:]:
        # Path + title
        m_link = re.search(r'<a\s+href="(/[^"]+)">([^<]+)</a>', block)
        if not m_link:
            continue
        path  = m_link.group(1).strip()
        title = m_link.group(2).strip()

        # Date ISO dans <time datetime="...">
        m_date = re.search(r'<time\s+datetime="(\d{4}-\d{2}-\d{2})', block)
        pub_date = _pdate(m_date.group(1)) if m_date else None

        results.append((path, title, pub_date))
    return results


def collect_bo_history(date_debut: date, date_fin: date) -> dict:
    """
    Collecte BO Social par scraping des pages sectorielles paginées.
    Sections : bo-sante et bo-travail.
    """
    source = "bo_social"
    seen = inserted = deduped = skipped = 0

    print(f"  BO Social : scraping pages sectorielles du {date_debut} au {date_fin}…")

    rows: list[dict] = []
    seen_paths: set[str] = set()

    for section in _BO_SECTIONS:
        page = 0
        while True:
            url = f"{_BO_BASE}/{section}{_BO_SORT_PARAMS}&page={page}"
            r = _get_http(url)
            if not r or r.status_code != 200:
                break

            articles = _parse_bo_page(r.text)
            if not articles:
                break

            in_range_count = 0
            for path, title, pub_date in articles:
                seen += 1
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                if pub_date is None:
                    skipped += 1
                    continue

                if pub_date > date_fin:
                    skipped += 1
                    continue

                if pub_date < date_debut:
                    skipped += 1
                    continue

                in_range_count += 1
                full_url = _BO_BASE + path
                rows.append(build_candidate_row(
                    source=source,
                    external_id=path,
                    official_url=full_url,
                    official_date=pub_date,
                    title_raw=title,
                    raw_payload={"path": path, "title": title, "date": str(pub_date), "section": section},
                ))

            # Stop si toute la page est plus ancienne que date_debut (tri DESC)
            dates_on_page = [pub_date for _, _, pub_date in articles if pub_date]
            oldest_on_page = min(dates_on_page) if dates_on_page else None
            if oldest_on_page and oldest_on_page < date_debut and in_range_count == 0:
                break

            page += 1
            time.sleep(0.2)

    inserted, deduped = _insert_bulk(rows)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ── Rapport ───────────────────────────────────────────────────────────────────

def _fmt(label: str, r: dict) -> str:
    if "error" in r:
        return f"  ❌ {label:<12} — ERREUR : {r['error']}"
    ins  = r.get("inserted", 0)
    dup  = r.get("deduped", 0)
    seen = r.get("seen", 0)
    skip = r.get("skipped", 0)
    status = "✅" if ins + dup > 0 else "⚠️ "
    return (
        f"  {status} {label:<12} — "
        f"{ins} nouveaux insérés, {dup} doublons ignorés "
        f"(vus={seen}, ignorés_filtre={skip})"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 65)
    print(f"  COLLECTE HISTORIQUE  {DATE_DEBUT} → {DATE_FIN}")
    print("=" * 65)
    t0 = time.time()

    report: dict[str, dict] = {}

    # ── JORF ──
    print("\n[1/4] JORF (PISTE API)")
    try:
        report["JORF"] = collect_jorf_history(DATE_DEBUT, DATE_FIN)
    except Exception as e:
        report["JORF"] = {"error": str(e)}
        print(f"  ERREUR: {e}")

    # ── HAS ──
    print("\n[2/4] HAS (RSS)")
    try:
        report["HAS"] = collect_has_history(DATE_DEBUT, DATE_FIN)
    except Exception as e:
        report["HAS"] = {"error": str(e)}
        print(f"  ERREUR: {e}")

    # ── ANSM ──
    print("\n[3/4] ANSM (scraping listing)")
    try:
        report["ANSM"] = collect_ansm_history(DATE_DEBUT, DATE_FIN)
    except Exception as e:
        report["ANSM"] = {"error": str(e)}
        print(f"  ERREUR: {e}")

    # ── BO Social ──
    print("\n[4/4] BO Social (scraping sectoriel)")
    try:
        report["BO Social"] = collect_bo_history(DATE_DEBUT, DATE_FIN)
    except Exception as e:
        report["BO Social"] = {"error": str(e)}
        print(f"  ERREUR: {e}")

    elapsed = time.time() - t0
    total_ins = sum(r.get("inserted", 0) for r in report.values())
    total_dup = sum(r.get("deduped", 0) for r in report.values())

    print("\n" + "=" * 65)
    print("  RAPPORT FINAL")
    print("=" * 65)
    for label, r in report.items():
        print(_fmt(label, r))
    print("-" * 65)
    print(f"  TOTAL : {total_ins} nouveaux insérés, {total_dup} doublons ignorés")
    print(f"  Durée : {elapsed:.1f}s")
    print("=" * 65)


if __name__ == "__main__":
    main()
