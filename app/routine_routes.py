# app/routine_routes.py
"""
Routes admin — Onglet Routine.

Déclenche manuellement les pipelines de collecte, spécialité par spécialité.

  Transversal (toutes spécialités) :
    POST /admin/routine/run/regulation       → job_collect_regulation()
    POST /admin/routine/run/recommendations  → job_collect_recommendations()

  Innovation par spécialité :
    POST /admin/routine/run/specialty/{slug} → collect_innovation_by_specialty(slug)
      filtre les sources dont specialty_hint == slug OU "tous",
      puis lance _run_llm_batch() avec le prompt spé-spécifique.

  LLM seul :
    POST /admin/routine/run/llm              → _run_llm_batch() sans collecte

  État :
    GET  /admin/routine/status               → counts + spécialités configurées
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

# Mapping pipeline → source_types (pour les stats globales)
_PIPELINE_SOURCE_TYPES: dict[str, tuple[str, ...]] = {
    "regulation":      ("reglementaire", "therapeutique"),
    "recommendations": ("recommandation",),
    "innovation":      ("innovation",),
}


# ---------------------------------------------------------------------------
# Helpers — liste des spécialités ayant des sources innovation configurées
# ---------------------------------------------------------------------------

def _get_configured_specialties() -> list[str]:
    """
    Retourne les spécialités opérationnelles : celles qui ont à la fois
      1. des sources dédiées (specialty_hint == slug dans PubMed/RSS), ET
      2. un addendum LLM configuré dans _SPECIALTY_ADDENDA.

    Les sources génériques (JAMA, NEJM…) ont des specialty_hint comme "cardiologie"
    mais sans addendum LLM dédié — elles ne sont pas encore opérationnelles.
    Quand une nouvelle spécialité est ajoutée (sources + addendum), elle apparaît
    automatiquement dans cet onglet.
    """
    try:
        from app.pubmed_collector import PUBMED_SOURCES
        from app.sources_innovation import ALL_INNOVATION_FEEDS
        from app.sources_presse_medicale import ALL_PRESSE_MEDICALE_FEEDS
        from app.llm_analysis import _SPECIALTY_ADDENDA
    except Exception:
        return []

    # Spécialités avec sources dédiées
    slugs_with_sources: set[str] = set()
    for src in PUBMED_SOURCES + ALL_INNOVATION_FEEDS + ALL_PRESSE_MEDICALE_FEEDS:
        hint = src.get("specialty_hint", "")
        if hint and hint != "tous":
            slugs_with_sources.add(hint)

    # Intersection : sources + addendum LLM
    operational = slugs_with_sources & set(_SPECIALTY_ADDENDA.keys())
    return sorted(operational)


# ---------------------------------------------------------------------------
# GET /admin/routine/status
# ---------------------------------------------------------------------------

@router.get("/status")
def routine_status(request: Request):
    """
    État du pipeline :
    - Spécialités innovation configurées (slugs avec sources dédiées)
    - Candidats NEW (non encore analysés LLM), toutes dates confondues
    - Items PENDING / APPROVED / REJECTED collectés dans les 10 derniers jours
    - Dernière date de collecte par spécialité (innovation) et par pipeline global
    - Répartition complète par spécialité (10 derniers jours)
    """
    _require_admin(request)

    since_10d = date.today() - timedelta(days=10)

    with get_conn() as conn:
        with conn.cursor() as cur:

            # 1. Candidats NEW par source (toutes dates — en attente d'analyse LLM)
            cur.execute("""
                SELECT source, COUNT(*) AS n
                FROM candidates
                WHERE status = 'NEW'
                GROUP BY source;
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

            # 3. Dernière collecte innovation par spécialité (MAX created_at sur tout l'historique)
            cur.execute("""
                SELECT i.specialty_slug, MAX(c.created_at)::date AS last_date
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.source_type = 'innovation'
                GROUP BY i.specialty_slug;
            """)
            last_by_specialty: dict[str, str] = {row[0]: str(row[1]) for row in cur.fetchall()}

            # 4. Dernière collecte par source_type global
            cur.execute("""
                SELECT i.source_type, MAX(c.created_at)::date AS last_date
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                GROUP BY i.source_type;
            """)
            last_by_stype: dict[str, str] = {row[0]: str(row[1]) for row in cur.fetchall()}

    # Mapper source → source_type pour compter les NEW par pipeline
    try:
        from app.llm_analysis import SOURCE_TO_TYPE
        from app.llm_analysis import SOURCE_SPECIALTY_HINTS
    except Exception:
        SOURCE_TO_TYPE = {}
        SOURCE_SPECIALTY_HINTS = {}

    # Aggréger les NEW par pipeline (regulation/recommendations/innovation)
    new_by_pipeline: dict[str, int] = {p: 0 for p in _PIPELINE_SOURCE_TYPES}
    # Et par spécialité (innovation)
    new_by_specialty: dict[str, int] = {}

    for source, count in new_by_source.items():
        stype = SOURCE_TO_TYPE.get(source, "")
        # → pipeline
        for pipeline, stypes in _PIPELINE_SOURCE_TYPES.items():
            if stype in stypes:
                new_by_pipeline[pipeline] += count
                break
        # → spécialité (sources innovation uniquement)
        if stype == "innovation":
            hint = SOURCE_SPECIALTY_HINTS.get(source, "tous")
            slug = hint if hint != "tous" else "__tous__"
            new_by_specialty[slug] = new_by_specialty.get(slug, 0) + count

    # Stats pipelines globaux (regulation + recommendations)
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

    # Stats par spécialité (items 10j)
    specialty_stats: dict[str, dict[str, Any]] = {}

    for source_type, specialty_slug, review_status, n in item_rows:
        # → pipeline global
        for pipeline, stypes in _PIPELINE_SOURCE_TYPES.items():
            if source_type in stypes:
                pipeline_stats[pipeline]["items"].setdefault(review_status, 0)
                pipeline_stats[pipeline]["items"][review_status] += n
                break
        # → par spécialité
        if specialty_slug:
            if specialty_slug not in specialty_stats:
                specialty_stats[specialty_slug] = {"items": {}, "new_candidates": 0, "last_collected": None}
            specialty_stats[specialty_slug]["items"].setdefault(review_status, 0)
            specialty_stats[specialty_slug]["items"][review_status] += n

    # Compléter les stats spécialité avec NEW candidates + last_collected
    for slug, stat in specialty_stats.items():
        stat["new_candidates"] = new_by_specialty.get(slug, 0) + new_by_specialty.get("__tous__", 0)
        stat["last_collected"] = last_by_specialty.get(slug)

    # Ajouter les spécialités configurées sans items récents (pour afficher la carte quand même)
    for slug in _get_configured_specialties():
        if slug not in specialty_stats:
            specialty_stats[slug] = {
                "items": {},
                "new_candidates": new_by_specialty.get(slug, 0) + new_by_specialty.get("__tous__", 0),
                "last_collected": last_by_specialty.get(slug),
            }

    return {
        "ok": True,
        "since": since_10d.isoformat(),
        "configured_specialties": _get_configured_specialties(),
        "pipelines": pipeline_stats,
        "specialties": specialty_stats,
    }


# ---------------------------------------------------------------------------
# POST /admin/routine/run/* — pipelines transversaux
# ---------------------------------------------------------------------------

@router.post("/run/regulation")
def run_regulation(request: Request):
    """
    Collecte réglementation (transversale — toutes spécialités) :
    JORF, KALI, LEGI, CIRCULAIRES, ANSM alertes/décisions, BO Social.
    Fenêtre 10 jours. Analyse LLM intégrée (le LLM assigne la spécialité).
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
    Collecte recommandations (transversale — toutes spécialités) :
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


# ---------------------------------------------------------------------------
# POST /admin/routine/run/specialty/{slug} — innovation par spécialité
# ---------------------------------------------------------------------------

@router.post("/run/specialty/{specialty_slug}")
def run_specialty(specialty_slug: str, request: Request):
    """
    Collecte innovation filtrée par spécialité :
      - Sources dont specialty_hint == slug OU "tous"
      - Analyse LLM avec le prompt spécifique à la spécialité (via _SPECIALTY_ADDENDA)
    Durée typique : 1-3 min selon le nombre de sources configurées.
    """
    _require_admin(request)

    configured = _get_configured_specialties()
    if specialty_slug not in configured:
        raise HTTPException(
            status_code=400,
            detail=f"Spécialité '{specialty_slug}' non configurée. "
                   f"Spécialités disponibles : {', '.join(configured)}",
        )

    try:
        from app.scheduler import collect_innovation_by_specialty
        result = collect_innovation_by_specialty(specialty_slug)
        return {"ok": True, "pipeline": "innovation", "specialty": specialty_slug, "result": result}
    except Exception as e:
        logger.exception("Erreur routine run-specialty %s", specialty_slug)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:300]}")


# ---------------------------------------------------------------------------
# POST /admin/routine/run/llm — LLM standalone
# ---------------------------------------------------------------------------

@router.post("/run/llm")
def run_llm(request: Request):
    """
    Relance l'analyse LLM seule (sans collecte) pour les candidats NEW en attente.
    Utile après une collecte dont l'analyse LLM a échoué partiellement.
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
