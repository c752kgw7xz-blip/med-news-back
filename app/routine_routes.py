# app/routine_routes.py
"""
Routes admin — Onglet Routine.

Déclenche manuellement les 3 pipelines de collecte (remplace les anciens crons).
Expose l'état courant : candidats NEW non analysés, items PENDING/APPROVED/REJECTED,
par pipeline et par spécialité.

GET  /admin/routine/status              → état pipeline
POST /admin/routine/run/regulation      → job_collect_regulation()
POST /admin/routine/run/recommendations → job_collect_recommendations()
POST /admin/routine/run/innovation      → job_collect_innovation()
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

# Mapping pipeline → source_types
_PIPELINE_SOURCE_TYPES: dict[str, tuple[str, ...]] = {
    "regulation":      ("reglementaire", "therapeutique"),
    "recommendations": ("recommandation",),
    "innovation":      ("innovation",),
}


# ---------------------------------------------------------------------------
# GET /admin/routine/status
# ---------------------------------------------------------------------------

@router.get("/status")
def routine_status(request: Request):
    """
    État du pipeline :
    - Candidats NEW (non encore analysés LLM), toutes dates confondues
    - Items PENDING / APPROVED / REJECTED collectés dans les 10 derniers jours
    - Dernière date de collecte par pipeline
    - Répartition par spécialité (10 derniers jours)
    """
    _require_admin(request)

    since_10d = date.today() - timedelta(days=10)

    with get_conn() as conn:
        with conn.cursor() as cur:

            # 1. Candidats NEW par source (toutes dates — ce sont des articles en attente d'analyse)
            cur.execute("""
                SELECT source, COUNT(*) AS n
                FROM candidates
                WHERE status = 'NEW'
                GROUP BY source
                ORDER BY source;
            """)
            new_by_source: dict[str, int] = {row[0]: row[1] for row in cur.fetchall()}

            # 2. Items par source_type × specialty_slug × review_status (10 derniers jours)
            cur.execute("""
                SELECT i.source_type, i.specialty_slug, i.review_status, COUNT(*) AS n
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE c.created_at >= %s
                GROUP BY i.source_type, i.specialty_slug, i.review_status
                ORDER BY i.source_type, i.specialty_slug, i.review_status;
            """, (since_10d,))
            item_rows = cur.fetchall()

            # 3. Dernière collecte par source_type (sur tout l'historique)
            cur.execute("""
                SELECT i.source_type, MAX(c.created_at)::date AS last_date
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                GROUP BY i.source_type;
            """)
            last_by_stype: dict[str, str] = {row[0]: str(row[1]) for row in cur.fetchall()}

    # Mapper source → source_type pour les candidats NEW
    try:
        from app.llm_analysis import SOURCE_TO_TYPE
    except Exception:
        SOURCE_TO_TYPE = {}

    # Aggréger les NEW par pipeline
    new_by_pipeline: dict[str, int] = {p: 0 for p in _PIPELINE_SOURCE_TYPES}
    for source, count in new_by_source.items():
        stype = SOURCE_TO_TYPE.get(source, "")
        for pipeline, stypes in _PIPELINE_SOURCE_TYPES.items():
            if stype in stypes:
                new_by_pipeline[pipeline] += count
                break

    # Construire les stats par pipeline
    pipeline_stats: dict[str, Any] = {}
    for pipeline, stypes in _PIPELINE_SOURCE_TYPES.items():
        last = max(
            (last_by_stype[st] for st in stypes if st in last_by_stype),
            default=None,
        )
        pipeline_stats[pipeline] = {
            "new_candidates": new_by_pipeline.get(pipeline, 0),
            "items": {},
            "last_collected": last,
        }

    # Remplir items + specialty depuis les rows
    specialty_stats: dict[str, dict[str, int]] = {}

    for source_type, specialty_slug, review_status, n in item_rows:
        # ── par pipeline ──
        for pipeline, stypes in _PIPELINE_SOURCE_TYPES.items():
            if source_type in stypes:
                pipeline_stats[pipeline]["items"].setdefault(review_status, 0)
                pipeline_stats[pipeline]["items"][review_status] += n
                break
        # ── par spécialité ──
        if specialty_slug:
            if specialty_slug not in specialty_stats:
                specialty_stats[specialty_slug] = {}
            specialty_stats[specialty_slug].setdefault(review_status, 0)
            specialty_stats[specialty_slug][review_status] += n

    return {
        "ok": True,
        "since": since_10d.isoformat(),
        "pipelines": pipeline_stats,
        "specialties": specialty_stats,
    }


# ---------------------------------------------------------------------------
# POST /admin/routine/run/*
# ---------------------------------------------------------------------------

@router.post("/run/regulation")
def run_regulation(request: Request):
    """
    Collecte réglementation :
    JORF, KALI, LEGI, CIRCULAIRES, ANSM alertes/décisions, BO Social.
    Fenêtre 10 jours. Analyse LLM intégrée.
    Durée typique : 1-3 min.
    """
    _require_admin(request)
    try:
        from app.scheduler import job_collect_regulation
        result = job_collect_regulation()
        return {"ok": True, "pipeline": "regulation", "result": result or {}}
    except Exception as e:
        logger.exception("Erreur routine run-regulation")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")


@router.post("/run/recommendations")
def run_recommendations(request: Request):
    """
    Collecte recommandations :
    HAS (RBP, CT, DM, accès précoce), sociétés savantes RSS,
    web scraping (ESC, EULAR, EAU, ESCMID…). Analyse LLM intégrée.
    Durée typique : 30-90 s.
    """
    _require_admin(request)
    try:
        from app.scheduler import job_collect_recommendations
        result = job_collect_recommendations()
        return {"ok": True, "pipeline": "recommendations", "result": result or {}}
    except Exception as e:
        logger.exception("Erreur routine run-recommendations")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")


@router.post("/run/innovation")
def run_innovation(request: Request):
    """
    Collecte innovation :
    PubMed (JTCVS, EJCTS, JACC, EHJ, JVS, EJVES, Circulation…),
    RSS presse médicale (TCTMD, Vascular News, Arch CV Dis…),
    RSS journaux (JAMA, NEJM, BMJ, Nature Med…). Analyse LLM intégrée.
    Durée typique : 1-3 min.
    """
    _require_admin(request)
    try:
        from app.scheduler import job_collect_innovation
        result = job_collect_innovation()
        return {"ok": True, "pipeline": "innovation", "result": result or {}}
    except Exception as e:
        logger.exception("Erreur routine run-innovation")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")


@router.post("/run/llm")
def run_llm(request: Request):
    """
    Relance l'analyse LLM seule (sans collecte) pour les candidats NEW en attente.
    Utile après un run de collecte dont l'analyse LLM a échoué partiellement.
    Durée typique : 30 s — 3 min selon le nombre de candidats.
    """
    _require_admin(request)
    try:
        from app.scheduler import _run_llm_batch
        _run_llm_batch()
        return {"ok": True, "pipeline": "llm"}
    except Exception as e:
        logger.exception("Erreur routine run-llm")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")
