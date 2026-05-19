# app/portal_routes.py
"""
Routes du portail médecin (authentifiées).

GET  /me           — Profil complet
GET  /articles     — Articles APPROVED (paginés, filtrés par spécialité)
GET  /articles/{id} — Détail article
POST /auth/verify-email       — Vérifie token email
POST /auth/resend-verification — Renvoie le mail de vérification
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, UploadFile, File
from pydantic import BaseModel

from app.db import get_conn
from app.security import (
    bearer_scheme, decode_access_token, decrypt_email,
    check_resend_verification_rate_limit,
    create_access_token, new_refresh_token, hash_refresh_token,
    refresh_ttl_seconds, new_csrf_token,
    verify_unsubscribe_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["portal"])

# ---------------------------------------------------------------------------
# Profils de praticiens — pour le filtrage croisé par type_praticien
# ---------------------------------------------------------------------------

# Spécialités interventionnelles (actes techniques invasifs)
_INTERVENTIONAL_SLUGS = frozenset({
    "chirurgie-vasculaire", "chirurgie-orthopedique", "chirurgie-thoracique",
    "chirurgie-plastique", "neurochirurgie", "chirurgie-pediatrique",
    "chirurgie-cardiaque", "anesthesiologie",
})

# Spécialités prescriptrices (médicaments en ambulatoire)
_PRESCRIPTEUR_SLUGS = frozenset({
    "medecine-generale", "cardiologie", "dermatologie", "endocrinologie",
    "gastro-enterologie", "gynecologie", "neurologie", "ophtalmologie", "orl",
    "pediatrie", "pneumologie", "psychiatrie", "rhumatologie", "urologie",
    "medecine-interne", "medecine-urgences", "geriatrie", "medecine-physique",
    "oncologie", "hematologie", "infectiologie", "nephrologie", "radiologie",
})


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def _get_current_user_id(creds=Depends(bearer_scheme)) -> str:
    payload = decode_access_token(creds.credentials)
    uid = payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="invalid token")
    return uid


def _require_active_access(user_id: str = Depends(_get_current_user_id)) -> str:
    """Vérifie que l'utilisateur a un accès actif (essai, abonnement ou plan étudiant)."""
    from datetime import datetime, timezone
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT trial_ends_at, subscribed_until, plan FROM users WHERE id = %s",
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="user not found")
    now = datetime.now(timezone.utc)
    trial_ok   = row[0] and row[0] > now
    sub_ok     = row[1] and row[1] > now
    student_ok = row[2] == 'student'
    if not trial_ok and not sub_ok and not student_ok:
        raise HTTPException(status_code=402, detail="subscription required")
    return user_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_user_specialty_slug(user_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.slug FROM users u
                LEFT JOIN specialties s ON s.slug = u.specialty_id
                WHERE u.id = %s;
            """, (user_id,))
            row = cur.fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# GET /me — Profil complet
# ---------------------------------------------------------------------------

@router.get("/me")
def get_profile(user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.id, u.email_ciphertext, u.email_verified_at, u.created_at,
                       s.slug AS specialty_slug, s.name AS specialty_name,
                       u.first_name, u.last_name, u.student_banner_seen
                FROM users u
                LEFT JOIN specialties s ON s.slug = u.specialty_id
                WHERE u.id = %s;
            """, (user_id,))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    email = decrypt_email(row[1])

    return {
        "user_id": str(row[0]),
        "email": email,
        "email_verified": row[2] is not None,
        "created_at": row[3].isoformat() if row[3] else None,
        "specialty_slug": row[4],
        "specialty_name": row[5],
        "first_name": row[6],
        "last_name": row[7],
        "student_banner_seen": bool(row[8]),
    }


@router.post("/me/push-token", status_code=204)
def save_push_token(
    payload: dict,
    user_id: str = Depends(_get_current_user_id),
):
    """Enregistre ou met à jour le token FCM/APNs de l'appareil."""
    token = (payload.get("token") or "").strip()
    platform = (payload.get("platform") or "android").strip().lower()
    if not token or platform not in ("android", "ios"):
        raise HTTPException(status_code=400, detail="token ou platform invalide")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO push_tokens (user_id, token, platform)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id, token) DO UPDATE
                    SET platform = EXCLUDED.platform,
                        updated_at = now()
                """,
                (user_id, token, platform),
            )


@router.post("/me/student-banner-seen", status_code=204)
def mark_student_banner_seen(user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET student_banner_seen = TRUE WHERE id = %s",
                (user_id,),
            )
        conn.commit()


# ---------------------------------------------------------------------------
# GET /articles — Articles APPROVED paginés
# ---------------------------------------------------------------------------

_VALID_SOURCE_TYPES = {"reglementaire", "recommandation", "innovation"}


def _build_audience_clause(audience: str | None, slug: str | None):
    """Return (where_clause, params_tuple) for audience filtering."""
    if slug == "pharmacien":
        # Pharmaciens voient : PHARMACIENS + prescripteur-type (médicaments) + leur slug + TL
        return (
            "(i.audience = 'PHARMACIENS'"
            " OR i.specialty_slug = 'pharmacien'"
            " OR i.type_praticien = 'prescripteur'"
            " OR i.audience = 'TRANSVERSAL_LIBERAL')",
            (),
        )
    elif slug:
        # Articles de la spécialité + transversaux tous médecins (exercice libéral, CNOM, CNAM…)
        return "(i.specialty_slug = %s OR i.audience = 'TRANSVERSAL_LIBERAL')", (slug,)
    else:
        return "(i.audience = 'SPECIALITE' OR i.audience = 'TRANSVERSAL_LIBERAL')", ()


@router.get("/articles")
def list_articles(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    specialty: Optional[str] = Query(default=None),
    audience: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    month: Optional[str] = Query(default=None),
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    source_type: Optional[str] = Query(default=None, description="reglementaire | recommandation | innovation"),
    user_id: str = Depends(_require_active_access),
):
    # Utiliser la spécialité demandée si fournie, sinon celle de l'utilisateur
    slug = specialty if specialty else _get_user_specialty_slug(user_id)
    aud_clause, aud_params = _build_audience_clause(audience, slug)

    # Build extra WHERE fragments
    extra_clauses: list[str] = []
    extra_params: list[Any] = []

    # Filtrage croisé type_praticien × spécialité
    # Les items sans type_praticien (NULL) passent toujours (rétrocompatibilité).
    # Les items TRANSVERSAL_LIBERAL sont exempts du filtre (pertinents pour tous).
    if slug in _INTERVENTIONAL_SLUGS:
        # Chirurgiens/anesthésistes : exclure articles prescripteurs sauf score très élevé (≥ 9)
        extra_clauses.append(
            "(i.audience = 'TRANSVERSAL_LIBERAL'"
            " OR i.type_praticien IS NULL"
            " OR i.type_praticien != 'prescripteur'"
            " OR i.score_density >= 9)"
        )
    elif slug in _PRESCRIPTEUR_SLUGS:
        # Prescripteurs : exclure articles interventionnels
        extra_clauses.append(
            "(i.audience = 'TRANSVERSAL_LIBERAL'"
            " OR i.type_praticien IS NULL"
            " OR i.type_praticien != 'interventionnel')"
        )

    # Filtre source_type (reglementaire | recommandation | innovation)
    _VALID_SOURCE_TYPES = {"reglementaire", "recommandation", "innovation"}
    if source_type and source_type in _VALID_SOURCE_TYPES:
        extra_clauses.append("COALESCE(i.source_type, 'innovation') = %s")
        extra_params.append(source_type)

    # Full-text search (ILIKE) — métacaractères LIKE échappés.
    # Escape char = '!' (1 seul char, compatible standard_conforming_strings=on).
    # '\\\\'  (ancien code) = 2 chars en SQL → PostgreSQL error "ESCAPE string must be 0 or 1 char".
    if search and search.strip():
        _s = search.strip().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{_s}%"
        extra_clauses.append(
            "(c.title_raw ILIKE %s ESCAPE '!' "
            "OR i.tri_json->>'titre_court' ILIKE %s ESCAPE '!' "
            "OR i.tri_json->>'resume' ILIKE %s ESCAPE '!')"
        )
        extra_params.extend([pattern, pattern, pattern])

    # Date range filter — from_date/to_date take priority over month.
    # Par défaut (aucun filtre explicite) : fenêtre mois courant + mois précédent.
    # Les items TRANSVERSAL_LIBERAL sont exempts du filtre de date UNIQUEMENT dans la
    # vue par défaut (fenêtre courante) — en vue d'archive (mois explicite ou from_date),
    # ils respectent les mêmes bornes pour ne pas apparaître dans le mauvais mois.
    TL = "i.audience = 'TRANSVERSAL_LIBERAL'"
    if from_date:
        extra_clauses.append("c.official_date >= %s")
        extra_params.append(from_date)
        if to_date:
            extra_clauses.append("c.official_date <= %s")
            extra_params.append(to_date)
    elif month and len(month) == 7:
        # Vue d'archive : filtre exact sur le mois demandé, TL inclus
        try:
            year, mon = int(month[:4]), int(month[5:7])
            from calendar import monthrange
            last_day = monthrange(year, mon)[1]
            start = f"{year:04d}-{mon:02d}-01"
            end = f"{year:04d}-{mon:02d}-{last_day}"
            extra_clauses.append("c.official_date >= %s AND c.official_date <= %s")
            extra_params.extend([start, end])
        except (ValueError, IndexError):
            pass
    else:
        # Fenêtre par défaut : 1er du mois précédent → aujourd'hui
        # TL exempt : ils sont toujours pertinents dans la vue courante
        today = date.today()
        if today.month == 1:
            default_from = date(today.year - 1, 12, 1)
        else:
            default_from = date(today.year, today.month - 1, 1)
        extra_clauses.append(f"({TL} OR c.official_date >= %s)")
        extra_params.append(default_from.isoformat())

    extra_where = (" AND " + " AND ".join(extra_clauses)) if extra_clauses else ""
    all_params = (*aud_params, *extra_params)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT COUNT(*) FROM (
                    SELECT DISTINCT i.candidate_id
                    FROM items i
                    JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND COALESCE(i.score_density, 0) >= 3
                      AND {aud_clause}{extra_where}
                ) _cnt
            """, all_params)
            total = cur.fetchone()[0]

            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT id, audience, specialty_slug, score_density,
                       tri_json, lecture_json, published_at,
                       title_raw, official_url, official_date,
                       categorie, source_type, source
                FROM (
                    SELECT DISTINCT ON (i.candidate_id)
                           i.id, i.audience, i.specialty_slug, i.score_density,
                           i.tri_json, i.lecture_json, i.published_at,
                           c.title_raw, c.official_url, c.official_date::text,
                           i.categorie, i.source_type, c.source
                    FROM items i
                    JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND COALESCE(i.score_density, 0) >= 3
                      AND {aud_clause}{extra_where}
                    ORDER BY i.candidate_id, i.score_density DESC
                ) deduped
                ORDER BY score_density DESC, official_date DESC
                LIMIT %s OFFSET %s;
            """, (*all_params, per_page, offset))
            rows = cur.fetchall()

    articles = []
    for r in rows:
        articles.append({
            "id": str(r[0]),
            "audience": r[1],
            "specialty_slug": r[2],
            "score_density": r[3],
            "tri_json": r[4],
            "lecture_json": r[5],
            "published_at": r[6].isoformat() if r[6] else None,
            "title_raw": r[7],
            "official_url": r[8],
            "official_date": r[9],
            "categorie": r[10],
            "source_type": r[11] or "reglementaire",
            "source": r[12] or "",
        })

    return {
        "articles": articles,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


# ---------------------------------------------------------------------------
# GET /articles/counts — Nombre d'articles APPROVED par spécialité
# ---------------------------------------------------------------------------

@router.get("/articles/counts")
def article_counts(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    user_id: str = Depends(_require_active_access),
):
    date_clause = ""
    date_params: list[Any] = []
    tl_date_clause = ""   # même logique mais TL exempt en vue défaut
    tl_date_params: list[Any] = []
    if from_date:
        date_clause += " AND c.official_date >= %s"
        date_params.append(from_date)
        tl_date_clause += " AND c.official_date >= %s"
        tl_date_params.append(from_date)
        if to_date:
            date_clause += " AND c.official_date <= %s"
            date_params.append(to_date)
            tl_date_clause += " AND c.official_date <= %s"
            tl_date_params.append(to_date)
    else:
        # Fenêtre par défaut : 1er du mois précédent → aujourd'hui
        # Items spé : filtrés ; TL : exempts (toujours visibles en vue courante)
        today = date.today()
        if today.month == 1:
            default_from = date(today.year - 1, 12, 1)
        else:
            default_from = date(today.year, today.month - 1, 1)
        date_clause += " AND c.official_date >= %s"
        date_params.append(default_from.isoformat())
        # tl_date_clause reste vide → pas de filtre date sur TL en vue défaut

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Count per specialty per source_type
            cur.execute(f"""
                SELECT i.specialty_slug, COALESCE(i.source_type, 'innovation'), COUNT(*)
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND i.specialty_slug IS NOT NULL
                  {date_clause}
                  AND CASE
                    WHEN i.specialty_slug = ANY(%s) THEN
                      (i.type_praticien IS NULL OR i.type_praticien != 'prescripteur' OR i.score_density >= 9)
                    WHEN i.specialty_slug = ANY(%s) THEN
                      (i.type_praticien IS NULL OR i.type_praticien != 'interventionnel')
                    ELSE TRUE
                  END
                GROUP BY i.specialty_slug, COALESCE(i.source_type, 'innovation');
            """, date_params + [list(_INTERVENTIONAL_SLUGS), list(_PRESCRIPTEUR_SLUGS)])
            per_spec: dict = {}
            for slug, stype, count in cur.fetchall():
                if slug not in per_spec:
                    per_spec[slug] = {"total": 0, "reglementaire": 0, "recommandation": 0, "innovation": 0}
                key = stype if stype in ("reglementaire", "recommandation", "innovation") else "reglementaire"
                per_spec[slug][key] = count
                per_spec[slug]["total"] += count

            # Compter les items TRANSVERSAL_LIBERAL — filtrés en vue archive, exempts en vue défaut
            cur.execute(f"""
                SELECT COALESCE(i.source_type, 'innovation'), COUNT(*)
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND i.audience = 'TRANSVERSAL_LIBERAL'
                  {tl_date_clause}
                GROUP BY COALESCE(i.source_type, 'innovation');
            """, tl_date_params)
            tous_counts: dict = {"total": 0, "reglementaire": 0, "recommandation": 0, "innovation": 0}
            for stype, count in cur.fetchall():
                key = stype if stype in ("reglementaire", "recommandation", "innovation") else "reglementaire"
                tous_counts[key] = count
                tous_counts["total"] += count

            # Injecter les TRANSVERSAL_LIBERAL dans chaque spécialité connue.
            # Les spés sans article spé-ciblé sur la période sont absentes de per_spec
            # → les initialiser à 0 pour qu'elles reçoivent quand même les comptes TL.
            all_known_slugs = _INTERVENTIONAL_SLUGS | _PRESCRIPTEUR_SLUGS | frozenset({
                "biologiste", "infirmiers", "kinesitherapie", "pharmacien",
                "sage-femme", "medecine-du-sport", "addictologie",
            })
            for slug in all_known_slugs:
                if slug not in per_spec:
                    per_spec[slug] = {"total": 0, "reglementaire": 0, "recommandation": 0, "innovation": 0}
            for spec_data in per_spec.values():
                for k in ("total", "reglementaire", "recommandation", "innovation"):
                    spec_data[k] = spec_data.get(k, 0) + tous_counts.get(k, 0)

    return {
        "per_specialty": per_spec,
        "tous_medecins": tous_counts,
    }


# ---------------------------------------------------------------------------
# GET /articles/months — Liste des mois avec nombre d'articles
# ---------------------------------------------------------------------------

@router.get("/articles/months")
def article_months(
    specialty: Optional[str] = Query(default=None),
    audience: Optional[str] = Query(default=None),
    source_type: Optional[str] = Query(default=None),
    user_id: str = Depends(_require_active_access),
):
    slug = specialty if specialty else _get_user_specialty_slug(user_id)
    aud_clause, aud_params = _build_audience_clause(audience, slug)

    extra_clauses = []
    extra_params: list = []
    if source_type and source_type in _VALID_SOURCE_TYPES:
        extra_clauses.append("COALESCE(i.source_type, 'innovation') = %s")
        extra_params.append(source_type)
    extra_sql = ("AND " + " AND ".join(extra_clauses)) if extra_clauses else ""

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT to_char(c.official_date, 'YYYY-MM') AS month,
                       COUNT(DISTINCT i.candidate_id)
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND c.official_date IS NOT NULL
                  AND {aud_clause}
                  {extra_sql}
                  AND CASE
                    WHEN i.audience = 'TRANSVERSAL_LIBERAL' THEN TRUE
                    WHEN i.specialty_slug = ANY(%s) THEN
                      (i.type_praticien IS NULL OR i.type_praticien != 'prescripteur' OR i.score_density >= 9)
                    WHEN i.specialty_slug = ANY(%s) THEN
                      (i.type_praticien IS NULL OR i.type_praticien != 'interventionnel')
                    ELSE TRUE
                  END
                GROUP BY month
                ORDER BY month DESC;
            """, list(aud_params) + extra_params + [list(_INTERVENTIONAL_SLUGS), list(_PRESCRIPTEUR_SLUGS)])
            rows = cur.fetchall()

    return {"months": [{"month": r[0], "count": r[1]} for r in rows]}


# ---------------------------------------------------------------------------
# GET /articles/{item_id} — Détail article
# ---------------------------------------------------------------------------

@router.get("/articles/{item_id}")
def get_article(
    item_id: str,
    user_id: str = Depends(_require_active_access),
):
    slug = _get_user_specialty_slug(user_id)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       i.tri_json, i.lecture_json, i.published_at,
                       c.title_raw, c.official_url, c.official_date::text, c.content_raw,
                       i.source_type, c.source
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.id = %s
                  AND i.review_status = 'APPROVED'
                  AND (%s IS NULL OR i.specialty_slug = %s);
            """, (item_id, slug, slug))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="article not found")

    return {
        "id": str(row[0]),
        "audience": row[1],
        "specialty_slug": row[2],
        "score_density": row[3],
        "tri_json": row[4],
        "lecture_json": row[5],
        "published_at": row[6].isoformat() if row[6] else None,
        "title_raw": row[7],
        "official_url": row[8],
        "official_date": row[9],
        "content_raw": row[10],
        "source_type": row[11],
        "source": row[12],
    }


# ---------------------------------------------------------------------------
# GET /favorites — Liste des item_id favoris de l'utilisateur connecté
# ---------------------------------------------------------------------------

@router.get("/favorites")
def list_favorites(user_id: str = Depends(_require_active_access)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT item_id FROM favorites WHERE user_id = %s;",
                (user_id,),
            )
            rows = cur.fetchall()
    return {"item_ids": [str(r[0]) for r in rows]}


# ---------------------------------------------------------------------------
# GET /favorites/articles — Données complètes des articles favoris (sans filtre spécialité)
# ---------------------------------------------------------------------------

@router.get("/favorites/articles")
def list_favorites_articles(user_id: str = Depends(_require_active_access)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, i.tri_json, i.source_type, i.specialty_slug,
                       c.title_raw, c.official_date::text, c.source
                FROM favorites f
                JOIN items i ON i.id = f.item_id
                JOIN candidates c ON c.id = i.candidate_id
                WHERE f.user_id = %s
                  AND i.review_status = 'APPROVED'
                ORDER BY f.created_at DESC;
            """, (user_id,))
            rows = cur.fetchall()
    return {"articles": [
        {
            "id": str(r[0]),
            "tri_json": r[1],
            "source_type": r[2],
            "specialty_slug": r[3],
            "title_raw": r[4],
            "official_date": r[5],
            "source": r[6],
        }
        for r in rows
    ]}


# ---------------------------------------------------------------------------
# POST /favorites/{item_id} — Ajoute un favori
# ---------------------------------------------------------------------------

@router.post("/favorites/{item_id}")
def add_favorite(item_id: str, user_id: str = Depends(_require_active_access)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO favorites (user_id, item_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, item_id) DO NOTHING;
                """,
                (user_id, item_id),
            )
    return {"status": "added"}


# ---------------------------------------------------------------------------
# DELETE /favorites/{item_id} — Supprime un favori
# ---------------------------------------------------------------------------

@router.delete("/favorites/{item_id}")
def remove_favorite(item_id: str, user_id: str = Depends(_require_active_access)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM favorites WHERE user_id = %s AND item_id = %s;",
                (user_id, item_id),
            )
    return {"status": "removed"}


# ---------------------------------------------------------------------------
# POST /articles/{item_id}/report — Signalement praticien
# ---------------------------------------------------------------------------

_VALID_REASONS = frozenset({"not_relevant", "factual_error", "wrong_specialty", "other"})

class ReportPayload(BaseModel):
    reason: str
    comment: str | None = None


@router.post("/articles/{item_id}/report")
def report_article(
    item_id: str,
    payload: ReportPayload,
    user_id: str = Depends(_require_active_access),
):
    if payload.reason not in _VALID_REASONS:
        raise HTTPException(status_code=422, detail=f"Raison invalide : {payload.reason}")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Vérifie que l'article existe
            cur.execute("SELECT id FROM items WHERE id = %s", (item_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Article introuvable")

            # Évite les doublons (un signalement par user par article)
            cur.execute(
                "SELECT id FROM item_reports WHERE item_id = %s AND user_id = %s",
                (item_id, user_id),
            )
            if cur.fetchone():
                return {"status": "already_reported"}

            cur.execute(
                """INSERT INTO item_reports (item_id, user_id, reason, comment)
                   VALUES (%s, %s, %s, %s)""",
                (item_id, user_id, payload.reason, payload.comment),
            )
    return {"status": "reported"}


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

class VerifyEmailPayload(BaseModel):
    token: str


def generate_verification_token(user_id: str) -> str:
    """Génère un token de vérification, le stocke en DB, retourne le token brut."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
                VALUES (%s, %s, %s);
            """, (user_id, token_hash, expires_at))

    return raw_token


def _build_verification_html(verify_url: str) -> str:
    """Construit le HTML de l'email de vérification — compatible tous clients mail."""
    return f"""\
<!DOCTYPE html>
<html lang="fr" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>Validez votre compte MedNews</title>
<!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#F5F4EF;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">

<!-- Fond global -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background-color:#F5F4EF;" bgcolor="#F5F4EF">
<tr><td align="center" style="padding:40px 16px;">

<!-- Container 600px -->
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
       style="max-width:600px;width:100%;background-color:#FDFCF9;border-radius:4px;overflow:hidden;border:1px solid #D6D2C8;"
       bgcolor="#FDFCF9">

<!-- Header avec logo texte -->
<tr>
<td align="center" style="padding:36px 40px 24px;border-bottom:1px solid #D6D2C8;background-color:#FDFCF9;" bgcolor="#FDFCF9">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td style="width:8px;height:8px;background-color:#9B2335;border-radius:50;" bgcolor="#9B2335">&nbsp;</td>
    <td style="padding-left:10px;">
      <span style="font-family:Georgia,'Times New Roman',serif;font-size:24px;font-weight:400;color:#1A1714;letter-spacing:-0.3px;">
        <em style="font-style:italic;">Med</em>News
      </span>
    </td>
  </tr>
  </table>
  <p style="margin:8px 0 0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:11px;color:#6A6258;letter-spacing:1.5px;text-transform:uppercase;">
    Veille r&eacute;glementaire m&eacute;dicale
  </p>
</td>
</tr>

<!-- Corps principal -->
<tr>
<td style="padding:40px 44px;background-color:#FDFCF9;" bgcolor="#FDFCF9">

  <!-- Titre -->
  <h1 style="margin:0 0 16px;font-family:Georgia,'Times New Roman',serif;font-size:26px;font-weight:400;color:#1A1714;line-height:1.3;">
    Bienvenue sur <em style="color:#9B2335;font-style:italic;">MedNews</em>
  </h1>

  <!-- Texte -->
  <p style="margin:0 0 8px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;font-weight:300;color:#3E3A34;line-height:1.7;">
    Votre compte a bien &eacute;t&eacute; cr&eacute;&eacute;. Pour acc&eacute;der &agrave; votre espace de veille
    r&eacute;glementaire, validez votre adresse email en cliquant sur le bouton ci-dessous.
  </p>
  <p style="margin:0 0 32px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:13px;font-weight:300;color:#6A6258;line-height:1.6;">
    Ce lien expire dans 24&nbsp;heures.
  </p>

  <!-- Bouton CTA -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto 24px;">
  <tr>
    <td align="center" style="background-color:#9B2335;border-radius:4px;" bgcolor="#9B2335">
      <!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" href="{verify_url}" style="height:48px;width:260px;v-text-anchor:middle;" arcsize="8%" fillcolor="#9B2335" stroke="f"><v:textbox inset="0,0,0,0"><center><![endif]-->
      <a href="{verify_url}"
         target="_blank"
         style="display:inline-block;padding:14px 36px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:4px;background-color:#9B2335;mso-padding-alt:14px 36px;">
        Valider mon compte &rarr;
      </a>
      <!--[if mso]></center></v:textbox></v:roundrect><![endif]-->
    </td>
  </tr>
  </table>

  <!-- Lien de secours -->
  <p style="margin:0 0 0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:12px;color:#6A6258;line-height:1.6;text-align:center;">
    Le bouton ne fonctionne pas&nbsp;? Copiez ce lien dans votre navigateur&nbsp;:<br>
    <a href="{verify_url}" style="color:#9B2335;text-decoration:underline;word-break:break-all;font-size:11px;">
      {verify_url}
    </a>
  </p>

</td>
</tr>

<!-- Séparateur -->
<tr>
<td style="padding:0 44px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr><td style="border-top:1px solid #D6D2C8;font-size:1px;line-height:1px;" height="1">&nbsp;</td></tr>
  </table>
</td>
</tr>

<!-- Footer -->
<tr>
<td style="padding:24px 44px 32px;background-color:#FDFCF9;" bgcolor="#FDFCF9">
  <p style="margin:0;font-family:'Courier New',Courier,monospace;font-size:10px;color:#6A6258;line-height:2;text-align:center;letter-spacing:0.3px;">
    MedNews &mdash; Veille r&eacute;glementaire pour m&eacute;decins lib&eacute;raux<br>
    &copy; 2026 MedNews. Tous droits r&eacute;serv&eacute;s.<br>
    <span style="color:#4E4840;">Cet email a &eacute;t&eacute; envoy&eacute; automatiquement, merci de ne pas y r&eacute;pondre.</span>
  </p>
</td>
</tr>

</table>
<!-- /Container -->

</td></tr>
</table>
<!-- /Fond global -->

</body>
</html>"""


def _build_verification_email_parts(raw_token: str) -> tuple[str, str, str]:
    """Construit subject, html, plain pour un token donné."""
    base_url = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
    verify_url = f"{base_url}/verify-email?token={raw_token}"
    subject = "MedNews — Vérifiez votre adresse email"
    html = _build_verification_html(verify_url)
    plain = (
        "Bienvenue sur MedNews !\n\n"
        "Validez votre compte en cliquant sur le lien ci-dessous :\n"
        f"{verify_url}\n\n"
        "Ce lien expire dans 24 heures.\n\n"
        "---\n"
        "MedNews — Veille réglementaire pour médecins libéraux\n"
        "Cet email a été envoyé automatiquement, merci de ne pas y répondre."
    )
    return subject, html, plain


def queue_verification_email(email: str, raw_token: str) -> None:
    """Insère l'email de vérification dans pending_emails pour envoi asynchrone."""
    subject, html, plain = _build_verification_email_parts(raw_token)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO pending_emails (to_email, subject, html_body, plain_body)
                VALUES (%s, %s, %s, %s)
            """, (email, subject, html, plain))
    logger.info("Email de vérification mis en queue pour %s", email[:3] + "***")


def send_verification_email(email: str, raw_token: str) -> None:
    """Envoie l'email de vérification directement (fallback / usage interne)."""
    from app.mailer import send_email
    subject, html, plain = _build_verification_email_parts(raw_token)
    try:
        result = send_email(email, subject, html, plain)
        if not result.success:
            logger.error("Échec envoi email vérification à %s : %s", email[:3] + "***", result.error)
        else:
            logger.info("Email de vérification envoyé à %s", email[:3] + "***")
    except Exception as e:
        logger.error("Exception envoi email vérification: %s", e)


@router.post("/auth/verify-email")
def verify_email(payload: VerifyEmailPayload, response: Response):
    import time as _time
    token_hash = _hash_token(payload.token)
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, user_id, expires_at, used_at
                FROM email_verification_tokens
                WHERE token_hash = %s;
            """, (token_hash,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=400, detail="Token invalide")

            token_id, user_id, expires_at, used_at = row

            if used_at is not None:
                raise HTTPException(status_code=400, detail="Token déjà utilisé")

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now > expires_at:
                raise HTTPException(status_code=400, detail="Token expiré")

            # Marquer le token comme utilisé + vérifier l'email
            cur.execute(
                "UPDATE email_verification_tokens SET used_at = %s WHERE id = %s;",
                (now, token_id),
            )
            cur.execute(
                "UPDATE users SET email_verified_at = %s WHERE id = %s;",
                (now, user_id),
            )

            # Récupérer is_admin pour le token
            cur.execute("SELECT is_admin FROM users WHERE id = %s;", (user_id,))
            user_row = cur.fetchone()
            is_admin = bool(user_row[0]) if user_row else False

            # Créer une session immédiate (refresh token)
            refresh = new_refresh_token()
            refresh_hash = hash_refresh_token(refresh)
            expires_ts = int(_time.time()) + refresh_ttl_seconds()
            cur.execute(
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, to_timestamp(%s))",
                (user_id, refresh_hash, expires_ts),
            )

    access = create_access_token(user_id=str(user_id), is_admin=is_admin)
    csrf = new_csrf_token()
    # Réutiliser set_auth_cookies depuis auth_routes
    from app.auth_routes import set_auth_cookies
    set_auth_cookies(response, refresh, csrf)

    return {"ok": True, "access_token": access, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# PATCH /me/name — Met à jour prénom et nom
# ---------------------------------------------------------------------------

class NameUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None


@router.patch("/me/name")
def update_name(payload: NameUpdate, user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET first_name = %s, last_name = %s WHERE id = %s;",
                (payload.first_name or None, payload.last_name or None, user_id),
            )
    return {"status": "updated"}


# PATCH /me/specialty — Met à jour la spécialité principale
# ---------------------------------------------------------------------------

class SpecialtyUpdate(BaseModel):
    specialty_slug: str


@router.patch("/me/specialty")
def update_specialty(payload: SpecialtyUpdate, user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT slug FROM specialties WHERE slug = %s;", (payload.specialty_slug,))
            if not cur.fetchone():
                raise HTTPException(status_code=400, detail="specialty not found")
            cur.execute(
                "UPDATE users SET specialty_id = %s WHERE id = %s;",
                (payload.specialty_slug, user_id),
            )
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# GET /me/preferences — Préférences newsletter
# ---------------------------------------------------------------------------

@router.get("/me/preferences")
def get_preferences(user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT notif_newsletter, notif_urgent, newsletter_frequency
                FROM users WHERE id = %s;
            """, (user_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {
        "notif_newsletter": row[0] if row[0] is not None else True,
        "notif_urgent": row[1] if row[1] is not None else False,
        "newsletter_frequency": row[2] or "monthly",
    }


# ---------------------------------------------------------------------------
# PATCH /me/preferences — Met à jour les préférences newsletter
# ---------------------------------------------------------------------------

class PreferencesUpdate(BaseModel):
    notif_newsletter: Optional[bool] = None
    notif_urgent: Optional[bool] = None
    newsletter_frequency: Optional[str] = None
    is_unsubscribed: Optional[bool] = None


@router.patch("/me/preferences")
def update_preferences(payload: PreferencesUpdate, user_id: str = Depends(_get_current_user_id)):
    fields: list[str] = []
    values: list = []
    if payload.notif_newsletter is not None:
        fields.append("notif_newsletter = %s")
        values.append(payload.notif_newsletter)
        fields.append("is_unsubscribed = %s")
        values.append(not payload.notif_newsletter)
    if payload.notif_urgent is not None:
        fields.append("notif_urgent = %s")
        values.append(payload.notif_urgent)
    if payload.newsletter_frequency is not None:
        fields.append("newsletter_frequency = %s")
        values.append(payload.newsletter_frequency)
    if payload.is_unsubscribed is not None:
        fields.append("is_unsubscribed = %s")
        values.append(payload.is_unsubscribed)
    if not fields:
        return {"status": "no changes"}
    values.append(user_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE users SET {', '.join(fields)} WHERE id = %s;",
                values,
            )
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

@router.post("/auth/resend-verification")
def resend_verification(user_id: str = Depends(_get_current_user_id)):
    check_resend_verification_rate_limit(user_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT email_ciphertext, email_verified_at FROM users WHERE id = %s;
            """, (user_id,))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    if row[1] is not None:
        return {"ok": True, "message": "Email déjà vérifié"}

    email = decrypt_email(row[0])

    raw_token = generate_verification_token(user_id)
    queue_verification_email(email, raw_token)

    return {"ok": True, "message": "Email de vérification envoyé"}


class ResendVerificationPublicPayload(BaseModel):
    email: str


@router.post("/auth/resend-verification-public")
def resend_verification_public(payload: ResendVerificationPublicPayload, request: Request):
    """Renvoie l'email de vérification sans JWT — rate limit par IP."""
    from app.main import normalize_email, email_lookup_hash
    from app.security import check_login_rate_limit

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    check_login_rate_limit(client_ip)

    email_norm = normalize_email(payload.email)
    lookup = email_lookup_hash(email_norm)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email_verified_at FROM users WHERE email_lookup = %s;",
                (lookup,),
            )
            row = cur.fetchone()

    if not row:
        # Ne pas révéler si l'email existe
        return {"ok": True, "message": "Si ce compte existe, un email vous a été envoyé."}

    user_id, verified_at = row
    if verified_at is not None:
        return {"ok": True, "message": "Ce compte est déjà vérifié. Vous pouvez vous connecter."}

    check_resend_verification_rate_limit(str(user_id))
    raw_token = generate_verification_token(str(user_id))
    queue_verification_email(email_norm, raw_token)

    return {"ok": True, "message": "Email de vérification renvoyé. Vérifiez vos spams."}


# ---------------------------------------------------------------------------
# Accès étudiant — upload carte + statut
# ---------------------------------------------------------------------------

_ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "application/pdf"}
_MAX_SIZE = 5 * 1024 * 1024  # 5 Mo


@router.post("/me/student-request", status_code=201)
async def upload_student_request(
    file: UploadFile = File(...),
    user_id: str = Depends(_get_current_user_id),
):
    if file.content_type not in _ALLOWED_MIME:
        raise HTTPException(status_code=415, detail="Format non supporté (JPEG, PNG, WebP, PDF)")

    data = await file.read()
    if len(data) > _MAX_SIZE:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (max 5 Mo)")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Une seule demande en attente ou approuvée à la fois
            cur.execute(
                "SELECT status FROM student_requests WHERE user_id = %s ORDER BY created_at DESC LIMIT 1",
                (user_id,),
            )
            existing = cur.fetchone()
            if existing and existing[0] in ("pending", "approved"):
                raise HTTPException(
                    status_code=409,
                    detail=f"Demande déjà en cours ({existing[0]})"
                )
            cur.execute(
                """
                INSERT INTO student_requests (user_id, document_data, document_mime)
                VALUES (%s, %s, %s) RETURNING id
                """,
                (user_id, data, file.content_type),
            )
            req_id = cur.fetchone()[0]
            # Accès limité à 48h en attente de validation admin
            cur.execute(
                "UPDATE users SET trial_ends_at = NOW() + INTERVAL '48 hours' WHERE id = %s",
                (user_id,),
            )
    return {"id": str(req_id), "status": "pending"}


@router.get("/me/student-request")
def get_student_request_status(user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, reject_reason, created_at
                FROM student_requests WHERE user_id = %s
                ORDER BY created_at DESC LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        return {"status": "none"}
    return {
        "id": str(row[0]),
        "status": row[1],
        "reject_reason": row[2],
        "created_at": row[3].isoformat() if row[3] else None,
    }


# ---------------------------------------------------------------------------
# GET /unsubscribe  — Désabonnement one-click (sans authentification)
# ---------------------------------------------------------------------------

from fastapi.responses import HTMLResponse

@router.get("/unsubscribe", response_class=HTMLResponse)
def one_click_unsubscribe(user_id: str, token: str):
    """Désabonne un utilisateur via un lien signé reçu par email."""
    if not verify_unsubscribe_token(token, user_id):
        return HTMLResponse(content=_unsubscribe_page(success=False), status_code=400)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET is_unsubscribed = TRUE, notif_newsletter = FALSE WHERE id = %s",
                (user_id,),
            )
        conn.commit()

    logger.info("Désabonnement one-click — user %s", user_id)
    return HTMLResponse(content=_unsubscribe_page(success=True), status_code=200)


def _unsubscribe_page(success: bool) -> str:
    if success:
        title   = "Vous êtes désabonné"
        message = "Vous ne recevrez plus les emails MedNews."
        detail  = "Vous pouvez réactiver les notifications à tout moment depuis vos paramètres."
        color   = "#1A6B5C"
        icon    = "✓"
    else:
        title   = "Lien invalide ou expiré"
        message = "Ce lien de désabonnement n'est plus valide."
        detail  = "Pour vous désabonner, connectez-vous et rendez-vous dans Paramètres → Notifications."
        color   = "#C0392B"
        icon    = "✗"

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — MedNews</title>
<style>
  body {{ margin:0; padding:0; background:#F9F7F4;
         font-family: 'Outfit', Helvetica, Arial, sans-serif;
         display:flex; align-items:center; justify-content:center; min-height:100vh; }}
  .card {{ background:#fff; border-radius:12px; padding:48px 40px; max-width:440px;
           text-align:center; box-shadow:0 2px 16px rgba(0,0,0,.08); }}
  .icon {{ font-size:48px; color:{color}; margin-bottom:16px; }}
  h1 {{ font-size:22px; color:#1A1A2E; margin:0 0 12px; }}
  p {{ font-size:15px; color:#555; line-height:1.6; margin:0 0 8px; }}
  .sub {{ font-size:13px; color:#999; }}
  a {{ color:#3B52A4; text-decoration:none; }}
  .logo {{ font-size:18px; font-weight:700; color:#1A1A2E; margin-bottom:32px; display:block; }}
  .logo span {{ color:#7C9EFF; }}
</style>
</head>
<body>
<div class="card">
  <a href="https://med-news.fr" class="logo">Med<span>News</span></a>
  <div class="icon">{icon}</div>
  <h1>{title}</h1>
  <p>{message}</p>
  <p class="sub">{detail}</p>
</div>
</body>
</html>"""
