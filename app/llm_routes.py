# app/llm_routes.py
"""
Routes admin pour le pipeline d'analyse LLM.

POST /admin/llm/run
    Analyse les candidats NEW (ou un candidat précis via ?candidate_id=…)
    → insère dans items (PENDING), met à jour candidates.status

GET  /admin/llm/stats
    Vue d'ensemble du pipeline (comptages par status)

GET  /admin/llm/pending
    Liste les items en attente de review (review_status = PENDING)

POST /admin/llm/review/{item_id}
    Valide ou rejette un item  { "decision": "APPROVED" | "REJECTED", "note": "..." }
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Optional

import psycopg
from psycopg.types.json import Json
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Query
from pydantic import BaseModel

from app.db import get_conn
from app.llm_analysis import analyse_candidate, LLM_MODEL, pre_filter_candidate, get_source_type, get_source_config
from app.security import bearer_scheme, decode_access_token, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/llm", tags=["llm"])

# _require_admin est importé depuis app.security (require_admin)
_require_admin = require_admin


# ---------------------------------------------------------------------------
# Modèles Pydantic
# ---------------------------------------------------------------------------

class ReviewPayload(BaseModel):
    decision: str          # "APPROVED" | "REJECTED"
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# SQL helpers
# ---------------------------------------------------------------------------

INSERT_ITEM_SQL = """
INSERT INTO items (
    candidate_id,
    audience,
    specialty_slug,
    tri_json,
    lecture_json,
    score_density,
    categorie,
    type_praticien,
    source_type,
    llm_raw,
    llm_model,
    review_status
)
VALUES (
    %(candidate_id)s,
    %(audience)s,
    %(specialty_slug)s,
    %(tri_json)s,
    %(lecture_json)s,
    %(score_density)s,
    %(categorie)s,
    %(type_praticien)s,
    %(source_type)s,
    %(llm_raw)s,
    %(llm_model)s,
    'PENDING'
)
ON CONFLICT (candidate_id, COALESCE(specialty_slug, '')) DO NOTHING
RETURNING id;
"""


def _fetch_candidates_to_analyse(cur, candidate_id: str | None, limit: int) -> list[dict]:
    """Retourne les candidats NEW à analyser."""
    if candidate_id:
        cur.execute(
            """
            SELECT id, title_raw, content_raw, official_date::text, source
            FROM candidates
            WHERE id = %s AND status IN ('NEW', 'LLM_FAILED')
            LIMIT 1;
            """,
            (candidate_id,),
        )
    else:
        cur.execute(
            """
            SELECT id, title_raw, content_raw, official_date::text, source
            FROM candidates
            WHERE status IN ('NEW', 'LLM_FAILED')
            ORDER BY official_date DESC
            LIMIT %s;
            """,
            (limit,),
        )
    rows = cur.fetchall()
    return [
        {
            "id": str(r[0]),
            "title_raw": r[1],
            "content_raw": r[2],
            "official_date": r[3],
            "source": r[4] or "",
        }
        for r in rows
    ]


def _process_one_candidate(candidate: dict) -> dict[str, Any]:
    """
    Analyse un candidat et insère le résultat dans items.
    Retourne un rapport {id, status, pertinent, specialites, score, error}.
    """
    cid = candidate["id"]
    report: dict[str, Any] = {"candidate_id": cid, "title": candidate["title_raw"][:80]}

    # Pré-filtre local (0 appel API)
    keep, drop_reason = pre_filter_candidate(candidate["title_raw"], source=candidate.get("source"))
    if not keep:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;",
                    (cid,),
                )
        report["status"] = "PRE_FILTERED"
        report["drop_reason"] = drop_reason
        logger.info("Pré-filtré %s : %s — %s", cid, drop_reason, candidate["title_raw"][:60])
        return report

    try:
        result = analyse_candidate(
            candidate_id=cid,
            title_raw=candidate["title_raw"],
            content_raw=candidate["content_raw"],
            official_date=candidate["official_date"],
            source=candidate.get("source"),
        )
    except Exception as e:
        logger.exception("LLM failed pour candidate %s", cid)
        # Marquer LLM_FAILED en base
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE candidates SET status = 'LLM_FAILED', llm_error = %s WHERE id = %s;",
                    (str(e)[:500], cid),
                )
        report["status"] = "LLM_FAILED"
        report["error"] = str(e)[:200]
        return report

    # Si non pertinent ou score trop faible → on marque LLM_DONE mais on n'insère pas dans items
    score = result.get("score_density", 0)
    min_score = get_source_config(candidate.get("source")).get("min_llm_score", 5)
    if not result.get("pertinent", True) or score < min_score:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;",
                    (cid,),
                )
        report["status"] = "LLM_DONE_NOT_PERTINENT"
        report["pertinent"] = False
        return report

    specialites: list[str] = result.get("specialites", [])
    audience: str = result.get("audience", "SPECIALITE")
    if audience not in ("SPECIALITE", "PHARMACIENS"):
        audience = "SPECIALITE"
    type_praticien: str | None = result.get("type_praticien")
    source_type: str = get_source_type(candidate.get("source"))

    # PHARMACIENS → 1 item avec specialty_slug = 'pharmacien'
    # SPECIALITE  → 1 item par spécialité (medecine-generale si aucune spécialité identifiée)
    if audience == "PHARMACIENS":
        slugs_to_insert: list[str | None] = ["pharmacien"]
    else:
        slugs_to_insert = specialites if specialites else ["medecine-generale"]

    llm_raw_text = json.dumps(result, ensure_ascii=False)
    item_ids: list[str] = []

    with get_conn() as conn:
        with conn.cursor() as cur:
            for slug in slugs_to_insert:
                params = {
                    "candidate_id": cid,
                    "audience": audience,
                    "specialty_slug": slug,
                    "tri_json": Json(result.get("tri_json", {})),
                    "lecture_json": Json(result.get("lecture_json", {})),
                    "score_density": result.get("score_density", 5),
                    "categorie": result.get("categorie", None),
                    "type_praticien": type_praticien,
                    "source_type": source_type,
                    "llm_raw": llm_raw_text,
                    "llm_model": result.get("llm_model", LLM_MODEL),
                }
                cur.execute(INSERT_ITEM_SQL, params)
                row = cur.fetchone()
                if row:
                    item_ids.append(str(row[0]))

            # Mettre à jour le statut du candidat
            cur.execute(
                "UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;",
                (cid,),
            )

    report["status"] = "LLM_DONE"
    report["pertinent"] = True
    report["audience"] = audience
    report["specialites"] = specialites
    report["score_density"] = result.get("score_density")
    report["item_ids"] = item_ids
    return report


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/run")
def run_llm_analysis(
    request: Request,
    candidate_id: Optional[str] = Query(default=None, description="Analyser un seul candidat"),
    limit: int = Query(default=20, ge=1, le=200, description="Nombre max de candidats à traiter"),
):
    """
    Lance l'analyse LLM sur les candidats NEW.
    - Sans paramètre : traite les `limit` plus récents candidats NEW
    - Avec candidate_id : traite uniquement ce candidat
    Protégé par x-admin-secret.
    """
    _require_admin(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            candidates = _fetch_candidates_to_analyse(cur, candidate_id, limit)

    if not candidates:
        return {
            "ok": True,
            "message": "Aucun candidat NEW à analyser",
            "processed": 0,
            "reports": [],
        }

    reports = []
    done = failed = not_pertinent = pre_filtered = 0

    for i, candidate in enumerate(candidates):
        logger.info("LLM [%d/%d] %s", i + 1, len(candidates), candidate["title_raw"][:60])
        report = _process_one_candidate(candidate)
        reports.append(report)

        if report["status"] == "PRE_FILTERED":
            pre_filtered += 1
        elif report["status"] == "LLM_DONE":
            done += 1
        elif report["status"] == "LLM_DONE_NOT_PERTINENT":
            not_pertinent += 1
        else:
            failed += 1

    return {
        "ok": True,
        "processed": len(candidates),
        "pre_filtered": pre_filtered,
        "done": done,
        "not_pertinent": not_pertinent,
        "failed": failed,
        "llm_calls": done + not_pertinent + failed,
        "reports": reports,
    }


@router.post("/reset-all")
def reset_all_pipeline(request: Request):
    """
    Nettoyage complet du pipeline LLM :
      1. Supprime TOUS les items (APPROVED + REJECTED + PENDING)
      2. Remet TOUS les candidats en status NEW (LLM_DONE + LLM_FAILED)
    → Permet de ré-analyser l'intégralité avec le prompt LLM actuel.
    ⚠️  Irréversible — à n'utiliser qu'en migration de prompt.
    """
    _require_admin(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Compter avant suppression
            cur.execute("SELECT COUNT(*) FROM items;")
            items_count = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM candidates WHERE status IN ('LLM_DONE', 'LLM_FAILED');"
            )
            candidates_count = cur.fetchone()[0]

            # Suppression items
            cur.execute("DELETE FROM items;")

            # Reset candidats
            cur.execute(
                """
                UPDATE candidates
                SET status = 'NEW', llm_error = NULL
                WHERE status IN ('LLM_DONE', 'LLM_FAILED');
                """
            )
            reset_count = cur.rowcount

        conn.commit()

    logger.warning(
        "reset-all : %d items supprimés, %d candidats remis en NEW", items_count, reset_count
    )

    return {
        "ok": True,
        "items_deleted": items_count,
        "candidates_reset_to_new": reset_count,
        "message": (
            f"{items_count} items supprimés. "
            f"{reset_count} candidats remis en NEW. "
            "Lance /admin/llm/run-all pour ré-analyser."
        ),
    }


class _RunBackgroundBody(BaseModel):
    max_candidates: int = 200
    batch_size: int = 20


@router.post("/run-background")
def run_background(request: Request, body: _RunBackgroundBody = _RunBackgroundBody()):
    """
    Lance le traitement LLM dans un thread séparé — retourne immédiatement.
    Le traitement continue côté serveur, requête non-bloquante.
    Consulte /admin/llm/stats pour suivre la progression.
    Body JSON : { "max_candidates": 200, "batch_size": 20 }
    """
    _require_admin(request)
    max_candidates = max(1, min(body.max_candidates, 10000))
    batch_size = max(1, min(body.batch_size, 100))

    def _bg_process(cap: int):
        try:
            logger.info("run-background : démarrage thread, cap=%d", cap)
            total = 0
            while total < cap:
                to_fetch = min(batch_size, cap - total)
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        candidates = _fetch_candidates_to_analyse(cur, None, to_fetch)
                if not candidates:
                    logger.info("run-background : terminé (NEW épuisés), %d traités", total)
                    break
                for candidate in candidates:
                    _process_one_candidate(candidate)
                    total += 1
                logger.info("run-background : %d/%d traités", total, cap)
            logger.info("run-background : arrêt — %d traités (plafond=%d)", total, cap)
        except Exception:
            logger.exception("run-background : ERREUR FATALE dans le thread")

    t = threading.Thread(target=_bg_process, args=(max_candidates,), daemon=True)
    t.start()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status = 'NEW';")
            remaining = cur.fetchone()[0]

    return {
        "ok": True,
        "message": f"Traitement lancé en arrière-plan — {min(max_candidates, remaining)} candidats à traiter ({remaining} NEW en attente au total).",
        "candidates_to_process": min(max_candidates, remaining),
        "candidates_remaining_total": remaining,
    }


@router.post("/pre-filter")
def run_pre_filter(request: Request):
    """
    Passe tous les candidats NEW au pré-filtre local (0 appel LLM).
    - Candidats non pertinents  → status = 'LLM_DONE'  (éliminés proprement)
    - Candidats pertinents      → restent en NEW         (prêts pour le LLM)
    Lance le traitement dans un thread séparé — retourne immédiatement.
    Consulte /admin/llm/stats pour suivre la progression (candidates_new diminue).
    """
    _require_admin(request)

    batch = 500

    def _bg_pre_filter():
        eliminated = kept = 0
        try:
            logger.info("pre-filter : démarrage thread background")
            while True:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, title_raw, source
                            FROM candidates
                            WHERE status = 'NEW'
                            ORDER BY id
                            LIMIT %s;
                            """,
                            (batch,),
                        )
                        rows = cur.fetchall()

                if not rows:
                    break

                to_eliminate: list[str] = []
                for (cid, title_raw, source) in rows:
                    keep, _ = pre_filter_candidate(title_raw or "", source=source or "")
                    if not keep:
                        to_eliminate.append(str(cid))
                    else:
                        kept += 1

                if to_eliminate:
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE candidates SET status = 'LLM_DONE' WHERE id = ANY(%s::uuid[]);",
                                (to_eliminate,),
                            )
                    eliminated += len(to_eliminate)

                logger.info("pre-filter : éliminés=%d conservés=%d (batch terminé)", eliminated, kept)

            logger.info("pre-filter : TERMINÉ — éliminés=%d conservés=%d", eliminated, kept)
        except Exception:
            logger.exception("pre-filter : ERREUR FATALE dans le thread")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status = 'NEW';")
            remaining = cur.fetchone()[0]

    t = threading.Thread(target=_bg_pre_filter, daemon=True)
    t.start()

    return {
        "ok": True,
        "started": True,
        "candidates_new_at_start": remaining,
        "message": (
            f"Pré-filtre lancé en arrière-plan sur {remaining} candidats NEW. "
            "Consulte /admin/llm/stats pour suivre (candidates_new diminue au fil du traitement)."
        ),
    }


@router.post("/run-all")
def run_llm_all(
    request: Request,
    batch_size: int = Query(default=10, ge=1, le=50, description="Taille de chaque lot"),
):
    """
    Traite TOUS les candidats NEW + LLM_FAILED par lots.
    Retourne le résumé global sans timeout.
    """
    _require_admin(request)

    total_done = total_failed = total_not_pertinent = total_processed = total_pre_filtered = 0

    while True:
        with get_conn() as conn:
            with conn.cursor() as cur:
                candidates = _fetch_candidates_to_analyse(cur, None, batch_size)

        if not candidates:
            break

        for candidate in candidates:
            total_processed += 1
            logger.info("LLM-ALL [%d] %s", total_processed, candidate["title_raw"][:60])
            report = _process_one_candidate(candidate)

            if report["status"] == "PRE_FILTERED":
                total_pre_filtered += 1
            elif report["status"] == "LLM_DONE":
                total_done += 1
            elif report["status"] == "LLM_DONE_NOT_PERTINENT":
                total_not_pertinent += 1
            else:
                total_failed += 1

    return {
        "ok": True,
        "processed": total_processed,
        "pre_filtered": total_pre_filtered,
        "done": total_done,
        "not_pertinent": total_not_pertinent,
        "failed": total_failed,
        "llm_calls": total_done + total_not_pertinent + total_failed,
    }


@router.get("/stats")
def llm_stats(request: Request):
    """
    Vue d'ensemble du pipeline.
    """
    _require_admin(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Candidates par status
            cur.execute(
                "SELECT status, COUNT(*) FROM candidates GROUP BY status ORDER BY status;"
            )
            candidate_stats = {row[0]: row[1] for row in cur.fetchall()}

            # Items par review_status
            cur.execute(
                "SELECT review_status, COUNT(*) FROM items GROUP BY review_status ORDER BY review_status;"
            )
            item_stats = {row[0]: row[1] for row in cur.fetchall()}

            # Items par spécialité
            cur.execute(
                """
                SELECT COALESCE(specialty_slug, 'TRANSVERSAL'), COUNT(*)
                FROM items
                GROUP BY specialty_slug
                ORDER BY COUNT(*) DESC;
                """
            )
            by_specialty = {row[0]: row[1] for row in cur.fetchall()}

            # Score moyen des items APPROVED
            cur.execute(
                "SELECT AVG(score_density) FROM items WHERE review_status = 'APPROVED';"
            )
            avg_score = cur.fetchone()[0]

    return {
        "ok": True,
        "candidates": candidate_stats,
        "items": item_stats,
        "items_by_specialty": by_specialty,
        "avg_score_approved": round(float(avg_score), 1) if avg_score else None,
    }


@router.get("/pending")
def list_pending(
    request: Request,
    specialty: Optional[str] = Query(default=None),
    min_score: int = Query(default=1, ge=1, le=10),
    limit: int = Query(default=50, ge=1, le=200),
):
    """
    Liste les items PENDING, optionnellement filtrés par spécialité et score minimum.
    Triés par score_density DESC puis date DESC.
    """
    _require_admin(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            params: list[Any] = ["PENDING", min_score]
            where_extra = ""

            if specialty:
                where_extra = "AND i.specialty_slug = %s "
                params.append(specialty)

            params.append(limit)

            cur.execute(
                f"""
                SELECT
                    i.id,
                    i.candidate_id,
                    i.audience,
                    i.specialty_slug,
                    i.score_density,
                    i.tri_json,
                    i.lecture_json,
                    i.review_status,
                    i.created_at,
                    c.title_raw,
                    c.official_url,
                    c.official_date,
                    i.categorie
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = %s
                  AND i.score_density >= %s
                  {where_extra}
                ORDER BY i.score_density DESC, c.official_date DESC
                LIMIT %s;
                """,
                params,
            )
            rows = cur.fetchall()

    items = []
    for row in rows:
        items.append({
            "item_id": str(row[0]),
            "candidate_id": str(row[1]),
            "audience": row[2],
            "specialty_slug": row[3],
            "score_density": row[4],
            "tri_json": row[5],
            "lecture_json": row[6],
            "review_status": row[7],
            "created_at": row[8].isoformat(),
            "title_raw": row[9],
            "official_url": row[10],
            "official_date": row[11].isoformat() if row[11] else None,
            "categorie": row[12],
        })

    return {"ok": True, "count": len(items), "items": items}


@router.post("/review/{item_id}")
def review_item(
    item_id: str,
    payload: ReviewPayload,
    request: Request,
):
    """
    Valide ou rejette un item.
    decision: "APPROVED" | "REJECTED"
    Un item APPROVED sera inclus dans la prochaine newsletter.
    """
    _require_admin(request)

    if payload.decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=400, detail="decision doit être APPROVED ou REJECTED")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE items
                SET
                    review_status = %s,
                    note_internal = %s,
                    published_at = CASE WHEN %s = 'APPROVED' THEN now() ELSE NULL END
                WHERE id = %s
                RETURNING id, review_status, specialty_slug, score_density;
                """,
                (payload.decision, payload.note, payload.decision, item_id),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="item non trouvé")

    return {
        "ok": True,
        "item_id": str(row[0]),
        "review_status": row[1],
        "specialty_slug": row[2],
        "score_density": row[3],
    }


# ---------------------------------------------------------------------------
# GET /admin/llm/items — All items (any status), filterable
# ---------------------------------------------------------------------------

@router.get("/items")
def list_items(
    request: Request,
    status: Optional[str] = Query(default=None, description="PENDING, APPROVED, REJECTED"),
    specialty: Optional[str] = Query(default=None),
    min_score: int = Query(default=1, ge=1, le=10),
    limit: int = Query(default=200, ge=1, le=500),
):
    """Liste tous les items, filtrables par status et spécialité."""
    _require_admin(request)

    with get_conn() as conn:
        with conn.cursor() as cur:
            conditions = ["i.score_density >= %s"]
            params: list[Any] = [min_score]

            if status:
                conditions.append("i.review_status = %s")
                params.append(status.upper())

            if specialty:
                conditions.append("i.specialty_slug = %s")
                params.append(specialty)

            params.append(limit)
            where = " AND ".join(conditions)

            cur.execute(
                f"""
                SELECT
                    i.id, i.candidate_id, i.audience, i.specialty_slug,
                    i.score_density, i.tri_json, i.lecture_json,
                    i.review_status, i.note_internal, i.created_at,
                    c.title_raw, c.official_url, c.official_date,
                    i.categorie
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE {where}
                ORDER BY i.review_status ASC, i.score_density DESC, c.official_date DESC
                LIMIT %s;
                """,
                params,
            )
            rows = cur.fetchall()

            # Also get counts by status
            cur.execute(
                "SELECT review_status, COUNT(*) FROM items GROUP BY review_status;"
            )
            counts = {r[0]: r[1] for r in cur.fetchall()}

    items = []
    for row in rows:
        items.append({
            "item_id": str(row[0]),
            "candidate_id": str(row[1]),
            "audience": row[2],
            "specialty_slug": row[3],
            "score_density": row[4],
            "tri_json": row[5],
            "lecture_json": row[6],
            "review_status": row[7],
            "note_internal": row[8],
            "created_at": row[9].isoformat() if row[9] else None,
            "title_raw": row[10],
            "official_url": row[11],
            "official_date": row[12].isoformat() if row[12] else None,
            "categorie": row[13],
        })

    return {"ok": True, "count": len(items), "counts": counts, "items": items}


# ---------------------------------------------------------------------------
# POST /admin/llm/newsletter/preview — HTML preview for a specialty
# ---------------------------------------------------------------------------

@router.post("/newsletter/preview")
def newsletter_preview(
    request: Request,
    specialty: Optional[str] = Query(default=None, description="Specialty slug"),
):
    """Génère un aperçu HTML de la newsletter pour une spécialité."""
    _require_admin(request)

    from app.newsletter_builder import build_newsletter

    with get_conn() as conn:
        with conn.cursor() as cur:
            conditions = ["i.review_status = 'APPROVED'"]
            params: list[Any] = []

            if specialty:
                conditions.append(
                    "(i.audience = 'TRANSVERSAL_LIBERAL' OR i.specialty_slug = %s)"
                )
                params.append(specialty)

            where = " AND ".join(conditions)
            cur.execute(
                f"""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       i.tri_json, i.lecture_json, i.published_at,
                       c.title_raw, c.official_url, c.official_date::text,
                       i.categorie
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE {where}
                ORDER BY i.score_density DESC, c.official_date DESC
                LIMIT 50;
                """,
                params,
            )
            rows = cur.fetchall()

    items = [
        {
            "audience": r[1],
            "specialty_slug": r[2],
            "score_density": r[3],
            "tri_json": r[4],
            "lecture_json": r[5],
            "title_raw": r[7],
            "official_url": r[8],
            "official_date": r[9],
            "categorie": r[10],
        }
        for r in rows
    ]

    subject, html, plain = build_newsletter(specialty, items)
    return {"ok": True, "subject": subject, "html": html, "article_count": len(items)}


# ---------------------------------------------------------------------------
# POST /admin/llm/newsletter/send-test — Send test email to admin
# ---------------------------------------------------------------------------

@router.post("/newsletter/send-test")
def newsletter_send_test(
    request: Request,
    specialty: Optional[str] = Query(default=None),
    email: str = Query(description="Recipient email for test"),
):
    """Envoie un email de test de la newsletter."""
    _require_admin(request)

    from app.newsletter_builder import build_newsletter
    from app.mailer import send_email

    with get_conn() as conn:
        with conn.cursor() as cur:
            conditions = ["i.review_status = 'APPROVED'"]
            params: list[Any] = []
            if specialty:
                conditions.append(
                    "(i.audience = 'TRANSVERSAL_LIBERAL' OR i.specialty_slug = %s)"
                )
                params.append(specialty)
            where = " AND ".join(conditions)
            cur.execute(
                f"""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       i.tri_json, i.lecture_json, i.published_at,
                       c.title_raw, c.official_url, c.official_date::text
                FROM items i JOIN candidates c ON c.id = i.candidate_id
                WHERE {where}
                ORDER BY i.score_density DESC
                LIMIT 50;
                """,
                params,
            )
            rows = cur.fetchall()

    items = [
        {
            "audience": r[1], "specialty_slug": r[2], "score_density": r[3],
            "tri_json": r[4], "lecture_json": r[5], "title_raw": r[7],
            "official_url": r[8], "official_date": r[9],
        }
        for r in rows
    ]

    subject, html, plain = build_newsletter(specialty, items)
    result = send_email(email, f"[TEST] {subject}", html, plain)

    return {
        "ok": result.success,
        "recipient": email,
        "article_count": len(items),
        "error": result.error,
    }
