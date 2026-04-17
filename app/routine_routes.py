# app/routine_routes.py
"""
Routes admin — Onglet Routine.

Un seul déclencheur par spécialité : collecte tout (innovation filtrée +
réglementation globale + recommandations globales) puis analyse LLM spé-spécifique.

GET  /admin/routine/status              → état + spécialités configurées
POST /admin/routine/run/specialty/{slug} → collect_by_specialty(slug)
POST /admin/routine/run/llm             → _run_llm_batch() seul (sans collecte)
"""

from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.db import get_conn
from app.security import require_admin as _require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/routine", tags=["routine"])


# ---------------------------------------------------------------------------
# Spécialités opérationnelles
# ---------------------------------------------------------------------------

def _get_configured_specialties() -> list[str]:
    """
    Retourne les spécialités opérationnelles : celles qui ont à la fois
      1. des sources dédiées (specialty_hint == slug dans PubMed/RSS), ET
      2. un addendum LLM dans _SPECIALTY_ADDENDA.
    Automatiquement mis à jour quand une nouvelle spécialité est configurée.
    """
    try:
        from app.pubmed_collector import PUBMED_SOURCES
        from app.sources_innovation import ALL_INNOVATION_FEEDS
        from app.sources_presse_medicale import ALL_PRESSE_MEDICALE_FEEDS
        from app.llm_analysis import _SPECIALTY_ADDENDA
    except Exception:
        return []

    slugs_with_sources: set[str] = set()
    for src in PUBMED_SOURCES + ALL_INNOVATION_FEEDS + ALL_PRESSE_MEDICALE_FEEDS:
        hint = src.get("specialty_hint", "")
        if hint and hint != "tous":
            slugs_with_sources.add(hint)

    operational = slugs_with_sources & set(_SPECIALTY_ADDENDA.keys())
    return sorted(operational)


# ---------------------------------------------------------------------------
# GET /admin/routine/status
# ---------------------------------------------------------------------------

@router.get("/status")
def routine_status(request: Request):
    """
    État par spécialité :
    - Candidats NEW non encore analysés (toutes dates)
    - Items PENDING / APPROVED / REJECTED (10 derniers jours)
    - Dernière collecte par spécialité
    """
    _require_admin(request)

    since_10d = date.today() - timedelta(days=10)

    with get_conn() as conn:
        with conn.cursor() as cur:

            # Candidats NEW par source
            cur.execute("""
                SELECT source, COUNT(*) AS n
                FROM candidates
                WHERE status = 'NEW'
                GROUP BY source;
            """)
            new_by_source: dict[str, int] = {row[0]: row[1] for row in cur.fetchall()}

            # Items par specialty_slug × review_status (10 derniers jours)
            cur.execute("""
                SELECT i.specialty_slug, i.review_status, COUNT(*) AS n
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE c.created_at >= %s
                GROUP BY i.specialty_slug, i.review_status;
            """, (since_10d,))
            item_rows = cur.fetchall()

            # Dernière collecte par spécialité (innovation — tout l'historique)
            cur.execute("""
                SELECT i.specialty_slug, MAX(c.created_at)::date AS last_date
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.source_type = 'innovation'
                GROUP BY i.specialty_slug;
            """)
            last_by_slug: dict[str, str] = {row[0]: str(row[1]) for row in cur.fetchall()}

    # Mapper source → specialty pour les candidats NEW innovation
    try:
        from app.llm_analysis import SOURCE_TO_TYPE, SOURCE_SPECIALTY_HINTS
    except Exception:
        SOURCE_TO_TYPE = {}
        SOURCE_SPECIALTY_HINTS = {}

    new_by_slug: dict[str, int] = {}
    for source, count in new_by_source.items():
        if SOURCE_TO_TYPE.get(source) == "innovation":
            hint = SOURCE_SPECIALTY_HINTS.get(source, "tous")
            key = hint if hint != "tous" else "__tous__"
            new_by_slug[key] = new_by_slug.get(key, 0) + count

    # Construire stats par spécialité
    specialty_stats: dict[str, dict[str, Any]] = {}

    for slug, review_status, n in item_rows:
        if not slug:
            continue
        if slug not in specialty_stats:
            specialty_stats[slug] = {"items": {}, "new_candidates": 0, "last_collected": None}
        specialty_stats[slug]["items"].setdefault(review_status, 0)
        specialty_stats[slug]["items"][review_status] += n

    # Ajouter new_candidates + last_collected
    for slug, stat in specialty_stats.items():
        stat["new_candidates"] = new_by_slug.get(slug, 0) + new_by_slug.get("__tous__", 0)
        stat["last_collected"] = last_by_slug.get(slug)

    # Garantir une entrée pour chaque spécialité configurée (même sans items récents)
    for slug in _get_configured_specialties():
        if slug not in specialty_stats:
            specialty_stats[slug] = {
                "items": {},
                "new_candidates": new_by_slug.get(slug, 0) + new_by_slug.get("__tous__", 0),
                "last_collected": last_by_slug.get(slug),
            }

    return {
        "ok": True,
        "since": since_10d.isoformat(),
        "configured_specialties": _get_configured_specialties(),
        "specialties": specialty_stats,
    }


# ---------------------------------------------------------------------------
# POST /admin/routine/run/specialty/{slug}
# ---------------------------------------------------------------------------

@router.post("/run/specialty/{specialty_slug}")
def run_specialty(specialty_slug: str, request: Request):
    """
    Collecte complète pour une spécialité :
      innovation (sources filtrées) + réglementation + recommandations + LLM.
    Durée typique : 2-5 min.
    """
    _require_admin(request)

    configured = _get_configured_specialties()
    if specialty_slug not in configured:
        raise HTTPException(
            status_code=400,
            detail=f"Spécialité '{specialty_slug}' non configurée. "
                   f"Disponibles : {', '.join(configured)}",
        )
    try:
        from app.scheduler import collect_by_specialty
        result = collect_by_specialty(specialty_slug)
        return {"ok": True, "specialty": specialty_slug, "result": result}
    except Exception as e:
        logger.exception("Erreur routine run-specialty %s", specialty_slug)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")


# ---------------------------------------------------------------------------
# POST /admin/routine/run/llm
# ---------------------------------------------------------------------------

@router.post("/run/llm")
def run_llm(request: Request):
    """
    Relance l'analyse LLM seule pour les candidats NEW en attente.
    Utile après une erreur partielle. Durée : 30 s — 3 min.
    """
    _require_admin(request)
    try:
        from app.scheduler import _run_llm_batch
        _run_llm_batch()
        return {"ok": True, "pipeline": "llm"}
    except Exception as e:
        logger.exception("Erreur routine run-llm")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")
