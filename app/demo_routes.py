# app/demo_routes.py
"""Routes publiques (sans auth) pour le mode démo."""
from __future__ import annotations
from datetime import date
from typing import Optional
from fastapi import APIRouter, Query
from app.db import get_conn
from app.portal_routes import _INTERVENTIONAL_SLUGS, _PRESCRIPTEUR_SLUGS

router = APIRouter(tags=["demo"])
DEMO_SPECIALTY = "chirurgie-vasculaire"

def _type_filter(slug: str) -> str:
    if slug in _INTERVENTIONAL_SLUGS:
        return " AND (i.type_praticien IS NULL OR i.type_praticien != 'prescripteur' OR i.score_density >= 9)"
    if slug in _PRESCRIPTEUR_SLUGS:
        return " AND (i.type_praticien IS NULL OR i.type_praticien != 'interventionnel')"
    return ""

def _fetch_demo_articles(slug: str, from_date: str, limit: int = 50) -> list[dict]:
    tf = _type_filter(slug)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT id, specialty_slug, score_density, tri_json, lecture_json,
                       title_raw, official_url, official_date, categorie, source_type, source
                FROM (
                    SELECT DISTINCT ON (i.candidate_id)
                           i.id, i.specialty_slug, i.score_density,
                           i.tri_json, i.lecture_json,
                           c.title_raw, c.official_url, c.official_date::text,
                           i.categorie, i.source_type, c.source
                    FROM items i
                    JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND COALESCE(i.score_density, 0) >= 3
                      AND i.specialty_slug = %s
                      AND c.official_date >= %s
                      {tf}
                    ORDER BY i.candidate_id, i.score_density DESC
                ) deduped
                ORDER BY source_type, official_date DESC, score_density DESC
                LIMIT %s
            """, (slug, from_date, limit))
            rows = cur.fetchall()
    return [
        {
            "id": str(r[0]), "specialty_slug": r[1], "score_density": r[2],
            "tri_json": r[3], "lecture_json": r[4], "title_raw": r[5],
            "official_url": r[6], "official_date": r[7], "categorie": r[8],
            "source_type": r[9] or "reglementaire", "source": r[10] or "",
        }
        for r in rows
    ]

@router.get("/demo/articles")
def demo_articles(specialty: str = Query(default=DEMO_SPECIALTY), per_page: int = Query(default=50, ge=1, le=100)):
    today = date.today()
    from_date = f"{today.year}-{today.month:02d}-01"
    articles = _fetch_demo_articles(specialty, from_date, per_page)
    return {"articles": articles, "total": len(articles), "from_date": from_date}

@router.get("/demo/counts")
def demo_counts(specialty: str = Query(default=DEMO_SPECIALTY)):
    today = date.today()
    from_date = f"{today.year}-{today.month:02d}-01"
    tf = _type_filter(specialty)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT COALESCE(i.source_type, 'reglementaire'), COUNT(DISTINCT i.candidate_id)
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND i.specialty_slug = %s
                  AND c.official_date >= %s
                  {tf}
                GROUP BY 1
            """, (specialty, from_date))
            rows = cur.fetchall()
    counts = {"reglementaire": 0, "recommandation": 0, "innovation": 0}
    for stype, n in rows:
        if stype in counts:
            counts[stype] = n
    counts["total"] = sum(counts.values())
    return counts
