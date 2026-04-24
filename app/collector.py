# app/collector.py
"""
Collecteur central — point d'entrée unique pour toutes les collectes de sources.

Dispatche selon la nature de la source :
  RSS    → rss_collector.collect_feed()           (ALL_FEEDS dans sources.py)
  PubMed → pubmed_collector.collect_pubmed_source() (PUBMED_SOURCES dans pubmed_collector.py)
  Web    → web_scraper.scrape_all_web()
  API    → fonctions _collect_* inline             (API_SOURCES dans sources.py)
             fda_pma  : open.fda.gov device/pma.json
             fda_510k : open.fda.gov device/510k.json
             eudamed  : ec.europa.eu/tools/eudamed/api
             ema_dhpc : ema.europa.eu — Dear HCP Communications (alertes sécurité)

Fonctions publiques :
  collect_all(days)                      → tout en une fois (RSS + PubMed + Web + API)
  collect_all_api(days)                  → API_SOURCES uniquement
  collect_by_specialty_sources(slug, days) → filtré par specialty_hint, sans LLM
"""

from __future__ import annotations

import logging
import os
import time
from datetime import date, timedelta
from typing import Any

import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn
from app.sources import ALL_FEEDS, API_SOURCES

logger = logging.getLogger(__name__)


# =============================================================================
# SECTION FDA — open.fda.gov
# API publique, pas de clé requise (240 req/min sans clé, 120k/j avec clé)
# =============================================================================

_FDA_BASE = "https://api.fda.gov"
_FDA_API_KEY = os.getenv("FDA_API_KEY", "")

_VASCULAR_KEYWORDS = [
    "aort",
    "endovascular",
    "endograft",
    "stent graft",
    "stentgraft",
    "fenestrated",
    "branched",
    "tevar",
    "evar",
    "fevar",
    "carotid",
    "iliac",
    "thoracic aneurysm",
    "abdominal aneurysm",
    "peripheral vascular",
    "peripheral arterial",
    "arteriovenous",
    "arterial graft",
    "vascular graft",
    "bypass graft",
    "inferior vena cava",
    "ivc filter",
    "thrombectomy",
    "embolectomy",
    "hemodialysis access",
    "dialysis access",
    "atherectomy",
    "angioplasty",
    "revascularization",
]


def _is_vascular(name: str, description: str = "") -> bool:
    text = f"{name} {description}".lower()
    return any(kw in text for kw in _VASCULAR_KEYWORDS)


def _fda_params(extra: dict) -> dict:
    p: dict = {}
    if _FDA_API_KEY:
        p["api_key"] = _FDA_API_KEY
    p.update(extra)
    return p


def _fda_date_range(days: int) -> str:
    since = (date.today() - timedelta(days=days)).strftime("%Y%m%d")
    today = date.today().strftime("%Y%m%d")
    return f"[{since}+TO+{today}]"


def _collect_fda_pma(days: int = 90, **_) -> dict[str, int]:
    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    params = _fda_params({
        "search": f'advisory_committee:"CH"+AND+decision_date:{_fda_date_range(days)}',
        "limit": 100,
        "skip": 0,
    })
    results: list[dict] = []
    try:
        with httpx.Client(follow_redirects=True) as client:
            while True:
                r = client.get(f"{_FDA_BASE}/device/pma.json", params=params, timeout=20)
                if r.status_code == 404:
                    break
                r.raise_for_status()
                data = r.json()
                batch = data.get("results", [])
                results.extend(batch)
                meta = data.get("meta", {}).get("results", {})
                total = meta.get("total", 0)
                skip = params["skip"] + len(batch)
                if skip >= total or len(batch) < 100:
                    break
                params["skip"] = skip
                time.sleep(0.3)
    except Exception as e:
        logger.warning("[fda_pma] fetch error: %s", e)
        return stats

    stats["fetched"] = len(results)
    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in results:
                try:
                    trade_name = item.get("trade_name") or ""
                    generic_name = item.get("generic_name") or ""
                    if not _is_vascular(trade_name, generic_name):
                        stats["skipped"] += 1
                        continue
                    pma_number = item.get("pma_number") or ""
                    if not pma_number:
                        stats["errors"] += 1
                        continue
                    date_str = item.get("decision_date") or ""
                    try:
                        pub_date = date(int(date_str[:4]), int(date_str[4:6]), int(date_str[6:8]))
                    except (ValueError, IndexError):
                        pub_date = date.today()
                    applicant = item.get("applicant") or ""
                    decision = item.get("decision_description") or item.get("decision") or "Approved"
                    supplement_type = item.get("supplement_type") or ""
                    title = f"[FDA PMA] {trade_name} — {generic_name}"
                    if supplement_type:
                        title += f" ({supplement_type})"
                    content = (
                        f"Fabricant : {applicant}\n"
                        f"Décision : {decision}\n"
                        f"Numéro PMA : {pma_number}\n"
                        f"Type : {supplement_type or 'Original'}\n"
                        f"Dispositif : {generic_name}"
                    )
                    official_url = (
                        f"https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfpma/pma.cfm?id={pma_number}"
                    )
                    row = build_candidate_row(
                        source="fda_pma",
                        external_id=pma_number,
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=content,
                        raw_payload={**item, "source": "fda_pma", "source_type": "innovation",
                                     "specialty_hint": "chirurgie-vasculaire"},
                    )
                    if insert_candidate(cur, row):
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1
                except Exception as e:
                    logger.warning("[fda_pma] insert error: %s", e)
                    stats["errors"] += 1
        conn.commit()
    logger.info("[fda_pma] done — %s", stats)
    return stats


def _collect_fda_510k(days: int = 90, **_) -> dict[str, int]:
    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    params = _fda_params({
        "search": f'advisory_committee:"CH"+AND+decision_date:{_fda_date_range(days)}',
        "limit": 100,
        "skip": 0,
    })
    results: list[dict] = []
    try:
        with httpx.Client(follow_redirects=True) as client:
            while True:
                r = client.get(f"{_FDA_BASE}/device/510k.json", params=params, timeout=20)
                if r.status_code == 404:
                    break
                r.raise_for_status()
                data = r.json()
                batch = data.get("results", [])
                results.extend(batch)
                meta = data.get("meta", {}).get("results", {})
                total = meta.get("total", 0)
                skip = params["skip"] + len(batch)
                if skip >= total or len(batch) < 100:
                    break
                params["skip"] = skip
                time.sleep(0.3)
    except Exception as e:
        logger.warning("[fda_510k] fetch error: %s", e)
        return stats

    stats["fetched"] = len(results)
    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in results:
                try:
                    device_name = item.get("device_name") or ""
                    applicant = item.get("applicant") or item.get("contact") or ""
                    if not _is_vascular(device_name):
                        stats["skipped"] += 1
                        continue
                    k_number = item.get("k_number") or ""
                    if not k_number:
                        stats["errors"] += 1
                        continue
                    date_str = item.get("decision_date") or ""
                    try:
                        pub_date = date(int(date_str[:4]), int(date_str[4:6]), int(date_str[6:8]))
                    except (ValueError, IndexError):
                        pub_date = date.today()
                    decision_description = item.get("decision_description") or "Substantially Equivalent"
                    title = f"[FDA 510k] {device_name}"
                    content = (
                        f"Fabricant : {applicant}\n"
                        f"Décision : {decision_description}\n"
                        f"Numéro 510(k) : {k_number}\n"
                        f"Dispositif : {device_name}"
                    )
                    official_url = (
                        f"https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfpmn/pmn.cfm?ID={k_number}"
                    )
                    row = build_candidate_row(
                        source="fda_510k",
                        external_id=k_number,
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=content,
                        raw_payload={**item, "source": "fda_510k", "source_type": "innovation",
                                     "specialty_hint": "chirurgie-vasculaire"},
                    )
                    if insert_candidate(cur, row):
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1
                except Exception as e:
                    logger.warning("[fda_510k] insert error: %s", e)
                    stats["errors"] += 1
        conn.commit()
    logger.info("[fda_510k] done — %s", stats)
    return stats


# =============================================================================
# SECTION EUDAMED — ec.europa.eu/tools/eudamed/api
# API publique, pas d'authentification pour la lecture.
# Rate limit non documenté — pause 0.5s entre requêtes par prudence.
# =============================================================================

_EUDAMED_BASE = "https://ec.europa.eu/tools/eudamed/api"
_VASCULAR_EMDN_CODES = ["E05", "E06", "E07"]
_EUDAMED_VASCULAR_KEYWORDS = _VASCULAR_KEYWORDS + [
    "endoprothèse",
    "prothèse vasculaire",
    "greffon vasculaire",
    "filtre cave",
    "stent périphérique",
    "vena cava filter",
]


def _search_eudamed_by_emdn(client: httpx.Client, emdn_code: str, since: date) -> list[dict]:
    all_results: list[dict] = []
    page = 1
    page_size = 100
    while True:
        payload = {
            "pageNumber": page,
            "pageSize": page_size,
            "filters": {
                "groupMedicalDeviceType": "MD",
                "riskClassification": ["Im"],
                "emdn": emdn_code,
            },
        }
        try:
            r = client.post(
                f"{_EUDAMED_BASE}/devices/basicUDI/search",
                json=payload,
                timeout=20,
            )
            if r.status_code in (404, 422):
                logger.warning("[eudamed] %d pour EMDN=%s — %s", r.status_code, emdn_code, r.text[:200])
                break
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.warning("[eudamed] fetch error EMDN=%s: %s", emdn_code, e)
            break

        batch: list[dict] = data.get("data") or data.get("results") or data.get("content") or []
        if not batch:
            break
        all_results.extend(batch)
        total = data.get("totalElements") or data.get("total") or data.get("totalCount") or 0
        if len(all_results) >= total or len(batch) < page_size:
            break
        page += 1
        time.sleep(0.5)
    return all_results


def _collect_eudamed(days: int = 90, **_) -> dict[str, int]:
    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    since = date.today() - timedelta(days=days)
    all_items: list[dict] = []

    with httpx.Client(
        follow_redirects=True,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "med-news-back/1.0 (contact@mednews.fr)",
        },
    ) as client:
        for emdn_code in _VASCULAR_EMDN_CODES:
            all_items.extend(_search_eudamed_by_emdn(client, emdn_code, since))
            time.sleep(0.5)

    stats["fetched"] = len(all_items)
    if not all_items:
        logger.info("[eudamed] aucun dispositif pour les %d derniers jours", days)
        return stats

    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in all_items:
                try:
                    eudamed_id = (
                        item.get("basicUdiDiId") or item.get("id")
                        or item.get("udiDi") or item.get("basicUDIDI") or ""
                    )
                    if not eudamed_id:
                        stats["errors"] += 1
                        continue

                    device_name = (
                        item.get("deviceName") or item.get("name")
                        or (item.get("tradeNames") or [{}])[0].get("deviceName", "")
                        or "(dispositif sans nom)"
                    )
                    description = (
                        item.get("shortDescription") or item.get("description")
                        or (item.get("emdn") or {}).get("description", "")
                        or ""
                    )
                    manufacturer = (
                        (item.get("manufacturer") or {}).get("name", "")
                        or item.get("manufacturerName", "") or ""
                    )

                    date_str = (
                        item.get("createdDate") or item.get("dateOfCertificate")
                        or item.get("certificateDate") or ""
                    )
                    pub_date = since
                    if date_str:
                        try:
                            pub_date = date.fromisoformat(date_str[:10])
                        except (ValueError, TypeError):
                            pass

                    if pub_date < since:
                        stats["skipped"] += 1
                        continue

                    kws = _VASCULAR_KEYWORDS + _EUDAMED_VASCULAR_KEYWORDS
                    text = f"{device_name} {description}".lower()
                    if not any(kw in text for kw in kws):
                        stats["skipped"] += 1
                        continue

                    risk_class = item.get("riskClassification") or item.get("riskClass") or "III"
                    official_url = (
                        f"https://ec.europa.eu/tools/eudamed/#/screen/devices/udi-di/{eudamed_id}"
                    )
                    title = f"[CE] {device_name}"
                    if manufacturer:
                        title += f" — {manufacturer}"
                    content = (
                        f"Fabricant : {manufacturer}\n"
                        f"Classe : {risk_class}\n"
                        f"Description : {description or device_name}\n"
                        f"ID EUDAMED : {eudamed_id}"
                    )
                    row = build_candidate_row(
                        source="eudamed",
                        external_id=str(eudamed_id),
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=content,
                        raw_payload={**item, "source": "eudamed", "source_type": "innovation",
                                     "specialty_hint": "chirurgie-vasculaire"},
                    )
                    if insert_candidate(cur, row):
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1
                except Exception as e:
                    logger.warning("[eudamed] insert error: %s", e)
                    stats["errors"] += 1
        conn.commit()
    logger.info("[eudamed] done — %s", stats)
    return stats


# =============================================================================
# SECTION EMA — ema.europa.eu JSON open data
# Endpoints statiques mis à jour 2×/jour (06h00 et 18h00 CET).
# Pas d'authentification, pas de clé. On télécharge la base complète
# et on filtre côté client par date.
# =============================================================================

_EMA_DHPC_URL = (
    "https://www.ema.europa.eu/en/documents/report/"
    "dhpc-output-json-report_en.json"
)

_EMA_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "med-news-back/1.0 (contact@mednews.fr)",
}


def _parse_ema_date(date_str: str) -> date | None:
    """DD/MM/YYYY → date. Retourne None si invalide."""
    try:
        d, m, y = date_str.strip().split("/")
        return date(int(y), int(m), int(d))
    except (ValueError, AttributeError):
        return None


def _ema_match_specialty(atc: str, ta_mesh: str, atc_prefixes: list[str], mesh_keywords: list[str]) -> bool:
    """Retourne True si l'item correspond aux filtres de spécialité.

    - atc_prefixes : liste de préfixes ATC à matcher (ex. ["N01", "N02A"])
    - mesh_keywords : liste de mots-clés à chercher dans therapeutic_area_mesh (insensible à la casse)
    - Si les deux listes sont vides → pas de filtre, tout passe.
    """
    if not atc_prefixes and not mesh_keywords:
        return True
    atc_upper = atc.upper()
    if any(atc_upper.startswith(p.upper()) for p in atc_prefixes):
        return True
    ta_lower = ta_mesh.lower()
    if any(kw.lower() in ta_lower for kw in mesh_keywords):
        return True
    return False


def _collect_ema_dhpc(days: int = 90, source_cfg: dict | None = None) -> dict[str, int]:
    """Dear Healthcare Professional Communications EMA dans la fenêtre `days`.
    """
    cfg = source_cfg or {}
    source_key = cfg.get("source", "ema_dhpc")
    specialty_hint = cfg.get("specialty_hint", "tous")
    atc_prefixes: list[str] = cfg.get("atc_prefixes", [])
    mesh_keywords: list[str] = cfg.get("mesh_keywords", [])
    log_tag = f"ema_dhpc:{source_key}"

    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    since = date.today() - timedelta(days=days)

    try:
        with httpx.Client(follow_redirects=True, headers=_EMA_HEADERS) as client:
            r = client.get(_EMA_DHPC_URL, timeout=30)
            r.raise_for_status()
            items: list[dict] = r.json()
    except Exception as e:
        logger.warning("[%s] fetch error: %s", log_tag, e)
        return stats

    stats["fetched"] = len(items)

    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in items:
                try:
                    if item.get("category", "").lower() != "human":
                        stats["skipped"] += 1
                        continue

                    pub_date = _parse_ema_date(item.get("dissemination_date", ""))
                    if pub_date is None or pub_date < since:
                        stats["skipped"] += 1
                        continue

                    atc = item.get("atc_code_human", "") or ""
                    ta_mesh = item.get("therapeutic_area_mesh", "") or ""
                    if not _ema_match_specialty(atc, ta_mesh, atc_prefixes, mesh_keywords):
                        stats["skipped"] += 1
                        continue

                    name = item.get("name_of_medicine", "") or "(sans nom)"
                    substance = item.get("active_substances", "") or ""
                    dhpc_type = item.get("dhpc_type", "") or ""
                    outcome = item.get("regulatory_outcome", "") or ""
                    dhpc_url = item.get("dhpc_url", "") or ""
                    nationally_auth = item.get("other_related_medicines_nationally_authorised", "") or ""

                    diss_date_raw = item.get("dissemination_date", "")
                    external_id = f"dhpc_{source_key}_{name}_{diss_date_raw}".replace(" ", "_").replace("/", "-")

                    if not dhpc_url:
                        stats["errors"] += 1
                        continue

                    title = f"[EMA DHPC] {name} — {dhpc_type}"
                    content_parts = [
                        f"Substance : {substance}",
                        f"Type d'alerte : {dhpc_type}",
                    ]
                    if outcome:
                        content_parts.append(f"Mesure réglementaire : {outcome}")
                    if ta_mesh:
                        content_parts.append(f"Aire thérapeutique : {ta_mesh}")
                    if atc:
                        content_parts.append(f"Code ATC : {atc}")
                    if nationally_auth:
                        content_parts.append(f"Médicaments nationaux concernés : {nationally_auth}")
                    content = "\n".join(content_parts)

                    row = build_candidate_row(
                        source=source_key,
                        external_id=external_id,
                        official_url=dhpc_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=content,
                        raw_payload={
                            **item,
                            "source": source_key,
                            "source_type": "reglementaire",
                            "specialty_hint": specialty_hint,
                        },
                    )
                    if insert_candidate(cur, row):
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1
                except Exception as e:
                    logger.warning("[%s] insert error: %s", log_tag, e)
                    stats["errors"] += 1
        conn.commit()
    logger.info("[%s] done — %s", log_tag, stats)
    return stats


# =============================================================================
# DISPATCH API
# =============================================================================

_API_DISPATCH: dict[str, Any] = {
    "fda_pma":   _collect_fda_pma,
    "fda_510k":  _collect_fda_510k,
    "eudamed":   _collect_eudamed,
    "ema_dhpc":  _collect_ema_dhpc,
}


def collect_all_api(days: int = 90) -> dict[str, dict]:
    """Collecte toutes les sources API (API_SOURCES dans sources.py).

    Passe `source_cfg` à chaque handler — les fonctions EMA s'en servent pour
    le filtrage par spécialité (atc_prefixes, mesh_keywords). Les fonctions
    FDA/EUDAMED l'ignorent via **_.
    """
    results: dict[str, dict] = {}
    for src in API_SOURCES:
        collector_key = src["collector"]
        fn = _API_DISPATCH.get(collector_key)
        if fn is None:
            logger.warning("[collector] pas de handler pour collector=%s", collector_key)
            continue
        try:
            results[src["source"]] = fn(days=days, source_cfg=src)
        except Exception as e:
            logger.error("[%s] erreur API : %s", src["source"], e)
            results[src["source"]] = {"error": str(e)}
    return results


# =============================================================================
# COLLECTE GLOBALE
# =============================================================================

def collect_all(days: int = 35) -> dict[str, Any]:
    """
    Lance l'intégralité de la collecte : RSS + PubMed + Web scraping + API.

    Utilisé par la route /collect/all et le job global.
    Les jours passés en argument s'appliquent à toutes les sources.
    Les sources API (FDA/EUDAMED) utilisent days=90 par défaut si days < 35
    pour capturer les approbations récentes (publications plus lentes).
    """
    from app.rss_collector import collect_all_rss
    from app.pubmed_collector import collect_all_pubmed
    from app.web_scraper import scrape_all_web

    report: dict[str, Any] = {}

    try:
        report["rss"] = collect_all_rss(days=days)
    except Exception as e:
        logger.error("[collector] RSS échoué : %s", e)
        report["rss"] = {"error": str(e)}

    try:
        report["pubmed"] = collect_all_pubmed(days=days)
    except Exception as e:
        logger.error("[collector] PubMed échoué : %s", e)
        report["pubmed"] = {"error": str(e)}

    try:
        report["web"] = scrape_all_web()
    except Exception as e:
        logger.error("[collector] Web scraping échoué : %s", e)
        report["web"] = {"error": str(e)}

    api_days = max(days, 90)
    try:
        report["api"] = collect_all_api(days=api_days)
    except Exception as e:
        logger.error("[collector] API échoué : %s", e)
        report["api"] = {"error": str(e)}

    return report


# =============================================================================
# COLLECTE PAR SPÉCIALITÉ (sources uniquement — sans LLM ni réglementation)
# =============================================================================

def collect_by_specialty_sources(specialty_slug: str, days: int = 2) -> dict[str, Any]:
    """
    Collecte toutes les sources d'innovation filtrées par specialty_hint.

    N'inclut PAS : analyse LLM, réglementation JORF/ANSM, recommandations HAS.
    Ces étapes restent dans scheduler.collect_by_specialty().

    Filtre : specialty_hint == slug OU specialty_hint == "tous"
    """
    from app.rss_collector import collect_feed
    from app.pubmed_collector import PUBMED_SOURCES, collect_pubmed_source

    def _matches(hint: str) -> bool:
        return hint == specialty_slug or hint == "tous"

    report: dict[str, Any] = {"specialty": specialty_slug, "days": days}

    # ── RSS (ALL_FEEDS filtré par spécialité) ────────────────────────────
    rss_results: dict = {}
    for feed in ALL_FEEDS:
        if _matches(feed.get("specialty_hint", "")):
            try:
                rss_results[feed["source"]] = collect_feed(feed, days=days)
            except Exception as e:
                rss_results[feed["source"]] = {"error": str(e)}
    report["rss"] = rss_results
    total_rss = sum(r.get("inserted", 0) for r in rss_results.values() if isinstance(r, dict))
    logger.info("[%s] RSS : %d sources, %d insérés", specialty_slug, len(rss_results), total_rss)

    # ── PubMed filtré par spécialité ─────────────────────────────────────
    pubmed_results: dict = {}
    for src in PUBMED_SOURCES:
        if _matches(src.get("specialty_hint", "")):
            try:
                pubmed_results[src["source"]] = collect_pubmed_source(src, days=days)
            except Exception as e:
                pubmed_results[src["source"]] = {"error": str(e)}
    report["pubmed"] = pubmed_results
    total_pub = sum(r.get("inserted", 0) for r in pubmed_results.values() if isinstance(r, dict))
    logger.info("[%s] PubMed : %d sources, %d insérés", specialty_slug, len(pubmed_results), total_pub)

    # ── API filtré par spécialité ─────────────────────────────────────────
    api_results: dict = {}
    api_days = max(days, 90)
    for src in API_SOURCES:
        if _matches(src.get("specialty_hint", "")):
            fn = _API_DISPATCH.get(src["collector"])
            if fn:
                try:
                    api_results[src["source"]] = fn(days=api_days)
                except Exception as e:
                    api_results[src["source"]] = {"error": str(e)}
    if api_results:
        report["api"] = api_results
        total_api = sum(r.get("inserted", 0) for r in api_results.values() if isinstance(r, dict))
        logger.info("[%s] API : %d sources, %d insérés", specialty_slug, len(api_results), total_api)

    return report
