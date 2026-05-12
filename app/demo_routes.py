# app/demo_routes.py
"""Routes publiques (sans auth) pour le mode démo — logique miroir du vrai portail."""
from __future__ import annotations
import calendar
from datetime import date
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

def _month_range(m: date) -> tuple[str, str]:
    last_day = calendar.monthrange(m.year, m.month)[1]
    return m.isoformat(), date(m.year, m.month, last_day).isoformat()

DEMO_PINNED_MONTH = date(2026, 4, 1)  # avril 2026 — mois de référence démo

def _latest_active_month(slug: str) -> tuple[str, str]:
    """Dernier mois avec articles APPROVED pour cette spécialité (ou TRANSVERSAL_LIBERAL).
    Pour la spécialité démo, épinglé à DEMO_PINNED_MONTH."""
    if slug == DEMO_SPECIALTY:
        return _month_range(DEMO_PINNED_MONTH)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DATE_TRUNC('month', c.official_date)::date
                FROM items i JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND (i.specialty_slug = %s OR i.audience = 'TRANSVERSAL_LIBERAL')
                ORDER BY 1 DESC LIMIT 1
            """, (slug,))
            row = cur.fetchone()
    if row and row[0]:
        return _month_range(row[0])
    today = date.today()
    return _month_range(date(today.year, today.month, 1))

def _fetch_demo_articles(slug: str, from_date: str, to_date: str, limit: int = 50) -> list[dict]:
    """Articles du dernier mois actif pour slug + TRANSVERSAL_LIBERAL (miroir du vrai portail)."""
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
                      AND (i.specialty_slug = %s OR i.audience = 'TRANSVERSAL_LIBERAL')
                      AND c.official_date >= %s
                      AND c.official_date <= %s
                      {tf}
                    ORDER BY i.candidate_id, i.score_density DESC
                ) deduped
                ORDER BY source_type, official_date DESC, score_density DESC
                LIMIT %s
            """, (slug, from_date, to_date, limit))
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

def _counts_for_month(slug: str, from_date: str, to_date: str) -> dict:
    """Counts par source_type pour slug + TRANSVERSAL_LIBERAL sur une période donnée."""
    tf = _type_filter(slug)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT COALESCE(i.source_type, 'reglementaire'), COUNT(DISTINCT i.candidate_id)
                FROM items i JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND (i.specialty_slug = %s OR i.audience = 'TRANSVERSAL_LIBERAL')
                  AND c.official_date >= %s
                  AND c.official_date <= %s
                  {tf}
                GROUP BY 1
            """, (slug, from_date, to_date))
            rows = cur.fetchall()
    counts = {"reglementaire": 0, "recommandation": 0, "innovation": 0}
    for stype, n in rows:
        if stype in counts:
            counts[stype] = n
    counts["total"] = sum(counts.values())
    return counts

@router.get("/demo/articles")
def demo_articles(specialty: str = Query(default=DEMO_SPECIALTY), per_page: int = Query(default=50, ge=1, le=100)):
    from_date, to_date = _latest_active_month(specialty)
    articles = _fetch_demo_articles(specialty, from_date, to_date, per_page)
    return {"articles": articles, "total": len(articles), "from_date": from_date, "to_date": to_date}

@router.get("/demo/counts")
def demo_counts(specialty: str = Query(default=DEMO_SPECIALTY)):
    from_date, to_date = _latest_active_month(specialty)
    counts = _counts_for_month(specialty, from_date, to_date)
    counts["from_date"] = from_date
    counts["to_date"] = to_date
    return counts

@router.get("/demo/counts-all")
def demo_counts_all():
    """Counts du dernier mois actif pour toutes les spés — une seule requête."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. Toutes les spés de la table specialties
            cur.execute("SELECT slug, name FROM specialties ORDER BY name")
            all_specs = cur.fetchall()

            # 2. Dernier mois actif par spécialité (incluant TL)
            cur.execute("""
                SELECT i.specialty_slug,
                       DATE_TRUNC('month', MAX(c.official_date))::date AS last_month
                FROM items i JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND i.specialty_slug IS NOT NULL
                GROUP BY i.specialty_slug
            """)
            last_months = {r[0]: r[1] for r in cur.fetchall()}

            # 3. TRANSVERSAL_LIBERAL : dernier mois actif global
            cur.execute("""
                SELECT DATE_TRUNC('month', MAX(c.official_date))::date
                FROM items i JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND i.audience = 'TRANSVERSAL_LIBERAL'
            """)
            tl_last = cur.fetchone()
            tl_last_month: date | None = tl_last[0] if tl_last else None

            result = {}
            for slug, name in all_specs:
                m = last_months.get(slug)
                # Prendre le mois le plus récent entre spé et TL
                if tl_last_month and (not m or tl_last_month > m):
                    m = tl_last_month
                if not m:
                    result[slug] = {"reglementaire": 0, "recommandation": 0, "innovation": 0, "total": 0,
                                    "from_date": None, "to_date": None, "name": name}
                    continue
                from_date, to_date = _month_range(m)
                tf = _type_filter(slug)
                cur.execute(f"""
                    SELECT COALESCE(i.source_type, 'reglementaire'), COUNT(DISTINCT i.candidate_id)
                    FROM items i JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND COALESCE(i.score_density, 0) >= 3
                      AND (i.specialty_slug = %s OR i.audience = 'TRANSVERSAL_LIBERAL')
                      AND c.official_date >= %s
                      AND c.official_date <= %s
                      {tf}
                    GROUP BY 1
                """, (slug, from_date, to_date))
                counts = {"reglementaire": 0, "recommandation": 0, "innovation": 0}
                for stype, n in cur.fetchall():
                    if stype in counts:
                        counts[stype] = n
                counts["total"] = sum(counts.values())
                counts["from_date"] = from_date
                counts["to_date"] = to_date
                counts["name"] = name
                result[slug] = counts
    return result
