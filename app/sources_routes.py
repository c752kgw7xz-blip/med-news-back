# app/sources_routes.py
"""
Routes admin pour gérer et tester les sources de collecte.

GET  /admin/sources/status
     État de chaque source : dernière collecte, nb candidats, erreurs

POST /admin/sources/collect/jorf
POST /admin/sources/collect/kali
POST /admin/sources/collect/has
POST /admin/sources/collect/ansm
POST /admin/sources/collect/spf
POST /admin/sources/collect/all       ← tout en une fois

POST /admin/sources/test-feed?url=…   ← tester un flux RSS manuellement
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.db import get_conn
from app.security import require_admin as _require_admin

router = APIRouter(prefix="/admin/sources", tags=["sources"])


# ---------------------------------------------------------------------------
# Statut global de toutes les sources
# ---------------------------------------------------------------------------

@router.get("/status")
def sources_status(request: Request):
    """
    Vue d'ensemble : pour chaque source, combien de candidats
    ont été insérés dans les 35 derniers jours.
    """
    _require_admin(request)

    since = date.today() - timedelta(days=35)

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

    # Regrouper par source
    by_source: dict[str, dict] = {}
    for source, status, count in rows:
        if source not in by_source:
            by_source[source] = {"total": 0, "by_status": {}}
        by_source[source]["by_status"][status] = count
        by_source[source]["total"] += count

    # Enrichir avec les métadonnées des sources connues
    known_sources = {
        # PISTE
        "legifrance_jorf":    {"label": "JORF — Journal Officiel",         "type": "piste_api",    "legal": "API officielle PISTE"},
        "piste_kali":         {"label": "KALI — Conventions collectives",  "type": "piste_api",    "legal": "API officielle PISTE"},
        "piste_legi":         {"label": "LEGI — Codes consolidés",         "type": "piste_api",    "legal": "API officielle PISTE"},
        "piste_circulaires":  {"label": "CIRCULAIRES — Ministère santé",   "type": "piste_api",    "legal": "API officielle PISTE"},
        # RSS
        "has_rbp":            {"label": "HAS — Recommandations bonne pratique", "type": "rss",     "legal": "Flux RSS public — Licence Ouverte"},
        "has_ct":             {"label": "HAS — Commission transparence",   "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "has_ap":             {"label": "HAS — Accès précoce",             "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "has_cert":           {"label": "HAS — Certification établissements", "type": "rss",       "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_actu":          {"label": "ANSM — Actualités",               "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_alertes":       {"label": "ANSM — Alertes de sécurité",      "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_decisions":     {"label": "ANSM — Décisions",                "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_ruptures":      {"label": "ANSM — Ruptures d'appro.",        "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_reco":          {"label": "ANSM — Recommandations",          "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "spf_actu":           {"label": "SPF — Actualités",                "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "spf_publi":          {"label": "SPF — Publications",              "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "spf_alertes":        {"label": "SPF — Alertes sanitaires",        "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
    }

    result = []
    for src_id, meta in known_sources.items():
        stats = by_source.get(src_id, {"total": 0, "by_status": {}})
        result.append({
            "source_id": src_id,
            **meta,
            "last_35_days": stats,
        })

    return {"ok": True, "since": since.isoformat(), "sources": result}


# ---------------------------------------------------------------------------
# Déclencheurs manuels par source
# ---------------------------------------------------------------------------

@router.post("/collect/jorf")
def collect_jorf(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.scheduler import job_collect_and_analyse
        # On réutilise le bloc JORF du scheduler directement
        from app.piste_routes import (
            _piste_call, _extract_list, _keep_item_with_reason,
            _parse_date10, _official_url,
        )
        from app.collector_utils import build_candidate_row, insert_candidate
        from datetime import timedelta

        source = "legifrance_jorf"
        today = date.today()
        start = today - timedelta(days=days)
        seen = ins = dup = 0

        with get_conn() as conn:
            with conn.cursor() as cur:
                for page in range(1, 41):
                    payload = {"fond": "JORF", "recherche": {
                        "pageNumber": page, "pageSize": 50,
                        "operateur": "ET", "typePagination": "DEFAUT",
                    }}
                    try:
                        data = _piste_call("/search", payload)
                    except Exception:
                        break
                    items = _extract_list(data)
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
                        ok, _ = _keep_item_with_reason(nature, title)
                        if not ok:
                            continue
                        pub_s = _parse_date10(it.get("datePublication")) or _parse_date10(it.get("date"))
                        if not pub_s:
                            continue
                        pub_d = date.fromisoformat(pub_s)
                        if not (start <= pub_d <= today):
                            continue
                        if not (isinstance(jorftext_id, str) and jorftext_id.startswith("JORFTEXT")):
                            continue
                        row = build_candidate_row(
                            source=source, external_id=jorftext_id,
                            official_url=_official_url(jorftext_id),
                            official_date=pub_d,
                            title_raw=(title or "").strip() or "(no title)",
                            jorftext_id=jorftext_id, raw_payload=it,
                        )
                        if insert_candidate(cur, row):
                            ins += 1
                        else:
                            dup += 1
            conn.commit()

        return {"ok": True, "source": "legifrance_jorf", "days": days,
                "seen": seen, "inserted": ins, "deduped": dup}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collect/kali")
def collect_kali(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.piste_collector import collect_kali as _collect
        return {"ok": True, "source": "piste_kali", **_collect(days=days)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collect/has")
def collect_has(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_has as _collect
        return {"ok": True, "source": "has", "results": _collect(days=days)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collect/ansm")
def collect_ansm(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_ansm as _collect
        return {"ok": True, "source": "ansm", "results": _collect(days=days)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collect/spf")
def collect_spf(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_spf as _collect
        return {"ok": True, "source": "spf", "results": _collect(days=days)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collect/all")
def collect_all(request: Request, days: int = Query(default=35, ge=1, le=365)):
    """Lance la collecte complète de toutes les sources."""
    _require_admin(request)
    try:
        from app.piste_collector import collect_all_piste_fonds
        from app.rss_collector import collect_all_rss
        return {
            "ok": True,
            "days": days,
            "piste_extra": collect_all_piste_fonds(days=days),
            "rss": collect_all_rss(days=days),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
