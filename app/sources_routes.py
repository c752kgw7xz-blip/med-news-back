# app/sources_routes.py
"""
Routes admin pour gérer et tester les sources de collecte.

GET  /admin/sources/status?days=120
     État de toutes les sources connues (700+) : nb candidats, statuts

POST /admin/sources/collect/all?days=120
     ← RUN PRINCIPAL — JORF + KALI + RSS (160) + PubMed (512) + Web + API

POST /admin/sources/collect/jorf       ← JORF seul (API PISTE)
POST /admin/sources/collect/kali       ← KALI seul (conventions médicales)
POST /admin/sources/collect/has        ← HAS seul (recommandations, CT, DM)
POST /admin/sources/collect/ansm       ← ANSM seul (sécurité, ruptures)
POST /admin/sources/collect/spf        ← SPF (non activé)
POST /admin/sources/collect/web        ← scraping HTML sociétés savantes FR + EU
POST /admin/sources/collect/innovation ← RSS + PubMed + Web + API (sans PISTE)
POST /admin/sources/collect/pratique   ← FR_REGULATORY + FR_SOCIETIES + Web FR
POST /admin/sources/collect/fda        ← FDA PMA + 510(k)
POST /admin/sources/collect/eudamed    ← EUDAMED classe III

POST /admin/sources/enrich/pubmed-abstracts  ← re-fetch abstracts manquants
POST /admin/sources/enrich/unpaywall         ← full text OA via Unpaywall + PMC

POST /admin/sources/test-feed?url=…   ← tester un flux RSS manuellement
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from datetime import date, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.db import get_conn
from app.security import require_admin as _require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/sources", tags=["sources"])


# ---------------------------------------------------------------------------
# Anti-SSRF : validation d'URL avant tout fetch externe
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_RANGES = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / métadonnées cloud
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),       # loopback IPv4
    ipaddress.ip_network("::1/128"),           # loopback IPv6
    ipaddress.ip_network("fc00::/7"),          # ULA IPv6
]


def _validate_url(url: str) -> None:
    """Vérifie que l'URL ne pointe pas vers des ressources internes (anti-SSRF)."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="URL invalide")
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise HTTPException(status_code=400, detail="Scheme non autorisé (http/https uniquement)")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname manquant dans l'URL")
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except OSError:
        raise HTTPException(status_code=400, detail="Impossible de résoudre le hostname")
    except Exception:
        raise HTTPException(status_code=400, detail="URL invalide")
    for blocked in _BLOCKED_RANGES:
        if ip in blocked:
            raise HTTPException(
                status_code=400,
                detail="Adresse IP bloquée (réseau privé ou métadonnées cloud)",
            )


# ---------------------------------------------------------------------------
# Statut global de toutes les sources
# ---------------------------------------------------------------------------

@router.get("/status")
def sources_status(request: Request, days: int = Query(default=120, ge=1, le=365)):
    """
    Vue d'ensemble : pour chaque source active, nombre de candidats insérés
    dans la fenêtre demandée (default 35 jours).

    Couvre toutes les sources du pipeline : RSS (160), PubMed (512),
    web scraping HTML (26), PISTE API (2), API externes (FDA, EUDAMED, EMA).
    """
    _require_admin(request)

    since = date.today() - timedelta(days=days)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source, status, COUNT(*) as n
                FROM candidates
                WHERE created_at >= %s
                GROUP BY source, status
                ORDER BY source, status;
            """, (since,))
            rows = cur.fetchall()

    by_source: dict[str, dict] = {}
    for src, status, count in rows:
        if src not in by_source:
            by_source[src] = {"total": 0, "by_status": {}}
        by_source[src]["by_status"][status] = count
        by_source[src]["total"] += count

    # ── Construire known_sources dynamiquement depuis les définitions de sources ──
    from app.sources import ALL_FEEDS, EU_WEB_SOURCES
    from app.web_scraper import WEB_SCRAPER_SOURCES
    from app.pubmed_collector import PUBMED_SOURCES

    known_sources: dict[str, dict] = {}

    # PISTE
    known_sources["legifrance_jorf"] = {
        "label": "JORF — Journal Officiel de la République Française",
        "section": "piste", "type": "piste_api", "legal": "API officielle PISTE",
    }
    known_sources["piste_kali"] = {
        "label": "KALI — Convention médicale et avenants UNCAM",
        "section": "piste", "type": "piste_api", "legal": "API officielle PISTE",
    }

    # RSS — toutes sections (FR_REGULATORY, FR_SOCIETIES, EU_FEEDS, JOURNALS, CLINICAL_PRESS)
    for feed in ALL_FEEDS:
        known_sources[feed["source"]] = {
            "label": feed.get("label", feed["source"]),
            "section": "rss",
            "type": "rss",
            "legal": "Flux RSS public",
        }

    # Web scraping HTML — sociétés européennes
    for src in EU_WEB_SOURCES:
        known_sources[src["source"]] = {
            "label": src.get("label", src["source"]),
            "section": "web_eu",
            "type": "web_scraper",
            "legal": "Scraping HTML public",
        }

    # Web scraping HTML — sociétés françaises
    for src in WEB_SCRAPER_SOURCES:
        known_sources[src["source"]] = {
            "label": src.get("label", src["source"]),
            "section": "web_fr",
            "type": "web_scraper",
            "legal": "Scraping HTML public",
        }

    # PubMed — 512 sources
    for src in PUBMED_SOURCES:
        known_sources[src["source"]] = {
            "label": src.get("label", src["source"]),
            "section": "pubmed",
            "type": "pubmed",
            "specialty": src.get("specialty_hint"),
            "legal": "API NCBI — accès libre (E-utilities)",
        }

    result = []
    for src_id, meta in known_sources.items():
        stats = by_source.get(src_id, {"total": 0, "by_status": {}})
        result.append({"source_id": src_id, **meta, f"last_{days}_days": stats})

    # Sources en DB non référencées dans les définitions connues
    unknown = [
        {"source_id": src_id, "section": "unknown", **stats}
        for src_id, stats in by_source.items()
        if src_id not in known_sources
    ]

    return {
        "ok": True,
        "since": since.isoformat(),
        "total_known_sources": len(known_sources),
        "total_with_data": sum(1 for r in result if r[f"last_{days}_days"]["total"] > 0),
        "sources": result,
        "unknown_sources": unknown,
    }


# ---------------------------------------------------------------------------
# Déclencheurs manuels par source
# ---------------------------------------------------------------------------

@router.post("/collect/jorf")
def collect_jorf(request: Request, days: int = Query(default=120, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.piste_collector import collect_jorf as _collect
        result = _collect(days=days)
        return {"ok": True, "source": "legifrance_jorf", "days": days, **result}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect/jorf")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/kali")
def collect_kali(request: Request, days: int = Query(default=120, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.piste_collector import collect_kali as _collect
        return {"ok": True, "source": "piste_kali", **_collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/has")
def collect_has(request: Request, days: int = Query(default=120, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_has as _collect
        return {"ok": True, "source": "has", "results": _collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/ansm")
def collect_ansm(request: Request, days: int = Query(default=120, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_ansm as _collect
        return {"ok": True, "source": "ansm", "results": _collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/spf")
def collect_spf(request: Request, days: int = Query(default=120, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_spf as _collect
        return {"ok": True, "source": "spf", "results": _collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/web")
def collect_web(request: Request):
    """
    Lance le scraping HTML des sociétés savantes sans flux RSS :
    SFH (hématologie), SFR (radiologie), SFO (ophtalmologie),
    SFPédiatrie, SOFCOT (orthopédie).
    Volume faible — pas de paramètre days (pas de date sur les pages).
    """
    _require_admin(request)
    try:
        from app.web_scraper import scrape_all_web
        results = scrape_all_web()
        total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
        total_errors = sum(1 for r in results.values() if isinstance(r, dict) and "error" in r)
        return {
            "ok": True,
            "total_inserted": total_inserted,
            "total_errors": total_errors,
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/innovation")
def collect_innovation(request: Request, days: int = Query(default=120, ge=1, le=365)):
    """
    Collecte toutes les sources innovation + API dispositifs médicaux (sans PISTE) :
    - RSS    : 160 feeds toutes spécialités (journaux, sociétés savantes, presse clinique)
    - PubMed : 512 sources toutes spécialités
    - Web    : scraping HTML sociétés savantes FR + EU
    - API    : FDA (PMA Class III + 510k), EUDAMED (classe III), EMA DHPC
    days=120 par défaut.
    Note : ne collecte pas JORF/KALI — utiliser /collect/all pour tout inclure.
    """
    _require_admin(request)
    try:
        from app.collector import collect_all
        report = collect_all(days=days)
        total_inserted = sum(
            r.get("inserted", 0)
            for section in report.values() if isinstance(section, dict)
            for r in section.values() if isinstance(r, dict)
        )
        return {"ok": True, "days": days, "total_inserted": total_inserted, **report}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect innovation")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/fda")
def collect_fda(request: Request, days: int = Query(default=120, ge=1, le=365)):
    """
    Collecte les approbations FDA de dispositifs médicaux :
    - PMA (Class III) : dispositifs à risque élevé (implants, endoprothèses…)
    - 510(k) (Class II) : dispositifs à risque modéré (clearances)
    Source : open.fda.gov (API publique, pas de clé requise).
    """
    _require_admin(request)
    try:
        from app.collector import _collect_fda_pma, _collect_fda_510k
        results = {"fda_pma": _collect_fda_pma(days=days), "fda_510k": _collect_fda_510k(days=days)}
        total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
        return {"ok": True, "days": days, "total_inserted": total_inserted, "results": results}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect fda")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/eudamed")
def collect_eudamed(request: Request, days: int = Query(default=120, ge=1, le=365)):
    """
    Collecte les dispositifs CE marqués dans EUDAMED (base UE).
    Filtre : Classe III (Im), codes EMDN pertinents + mots-clés cliniques côté client.
    Source : https://ec.europa.eu/tools/eudamed/ (API publique).
    """
    _require_admin(request)
    try:
        from app.collector import _collect_eudamed
        result = _collect_eudamed(days=days)
        return {"ok": True, "days": days, **result}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect eudamed")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/enrich/pubmed-abstracts")
def enrich_pubmed_abstracts(request: Request):
    """
    Re-fetche les abstracts PubMed pour les candidats en DB sans content_raw.

    Cas d'usage : après un run de collecte où NCBI a renvoyé des timeouts ou
    des rate-limits, certains articles ont été insérés sans abstract.
    Cette route les retrouve et les enrichit via l'API NCBI efetch.

    Ne touche pas aux candidats déjà traités (LLM_DONE, APPROVED, REJECTED).
    """
    _require_admin(request)
    try:
        from app.pubmed_collector import enrich_empty_abstracts
        stats = enrich_empty_abstracts()
        return {"ok": True, **stats}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur enrich pubmed-abstracts")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/enrich/unpaywall")
def enrich_unpaywall(
    request: Request,
    limit: int = Query(default=200, ge=1, le=500, description="Nombre max de candidats à enrichir"),
):
    """
    Enrichit le content_raw des candidats PubMed via Unpaywall + Europe PMC.

    Pour chaque candidat pubmed_* avec un DOI mais un abstract court (< 1 200 chars),
    tente de récupérer le full text en open access :
      1. Unpaywall (api.unpaywall.org) → URL OA légale
      2. Europe PMC (fullTextXML) → texte complet parsé depuis JATS XML
      3. Fallback HTML : page auteur / preprint si disponible

    Content_raw n'est mis à jour que si le full text apporte au moins 2× plus de contenu
    que l'abstract actuel.

    Typiquement : ~35 % des RCTs sont en open access via PMC (mandats NIH/EU).
    """
    _require_admin(request)
    try:
        from app.unpaywall_client import enrich_with_unpaywall
        stats = enrich_with_unpaywall(limit=limit)
        return {"ok": True, **stats}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur enrich unpaywall")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/all")
def collect_all(request: Request, days: int = Query(default=120, ge=1, le=365)):
    """
    Lance la collecte complète de toutes les sources :
    - PISTE  : JORF + KALI (API Légifrance)
    - RSS    : 160 feeds (FR_REGULATORY, FR_SOCIETIES, EU, JOURNALS, CLINICAL_PRESS)
    - PubMed : 512 sources (tous specialty_hints, fenêtre = days)
    - Web    : scraping HTML sociétés savantes FR + EU (ESC, EULAR, EAU…)
    - API    : FDA (PMA + 510k), EUDAMED (classe III), EMA DHPC — fenêtre max(days, 90)

    Pour le run initial (matelas 2026) utiliser days=120.
    """
    _require_admin(request)
    try:
        from app.piste_collector import collect_all_piste_fonds
        from app.collector import collect_all as _collect_all

        piste = collect_all_piste_fonds(days=days)
        rest  = _collect_all(days=days)   # RSS + PubMed + Web + API

        total_inserted = (
            sum(v.get("inserted", 0) for v in piste.values() if isinstance(v, dict))
            + sum(
                r.get("inserted", 0)
                for section in rest.values() if isinstance(section, dict)
                for r in (section.values() if isinstance(section, dict) else [])
                if isinstance(r, dict)
            )
        )
        return {
            "ok": True,
            "days": days,
            "total_inserted": total_inserted,
            "piste": piste,
            **rest,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect/all")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/pratique")
def collect_pratique(request: Request, days: int = Query(default=120, ge=1, le=365)):
    """
    Collecte uniquement les sources pratiques médicales :
    recommandations HAS, bon usage ANSM, sociétés savantes, académie de médecine.
    days=120 par défaut.
    """
    _require_admin(request)
    try:
        from app.rss_collector import collect_pratique as _collect
        results = _collect(days=days)
        total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
        total_errors = sum(r.get("errors", 0) for r in results.values() if isinstance(r, dict))
        return {
            "ok": True,
            "days": days,
            "total_inserted": total_inserted,
            "total_errors": total_errors,
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


# ---------------------------------------------------------------------------
# Test d'un flux RSS arbitraire
# ---------------------------------------------------------------------------

@router.post("/test-feed")
def test_rss_feed(
    request: Request,
    url: str = Query(..., description="URL du flux RSS à tester"),
):
    """
    Teste un flux RSS : retourne les 5 premières entrées sans rien insérer en base.
    Utile pour vérifier qu'un nouveau flux est lisible avant de l'activer.
    """
    _require_admin(request)

    _validate_url(url)

    try:
        from app.rss_collector import fetch_feed, _entry_title, _parse_entry_date, _entry_url

        parsed = fetch_feed(url)
        if parsed is None:
            return {"ok": False, "error": "Impossible de récupérer le flux"}

        entries = (parsed.entries or [])[:5]
        sample = []
        for e in entries:
            sample.append({
                "title": _entry_title(e),
                "url": _entry_url(e),
                "date": str(_parse_entry_date(e)),
            })

        feed_meta = {}
        if hasattr(parsed, "feed"):
            feed_meta = {
                "title": getattr(parsed.feed, "title", ""),
                "description": getattr(parsed.feed, "description", ""),
                "link": getattr(parsed.feed, "link", ""),
            }

        return {
            "ok": True,
            "feed": feed_meta,
            "total_entries": len(parsed.entries or []),
            "sample": sample,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")
