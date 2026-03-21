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
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.db import get_conn
from app.security import bearer_scheme, decode_access_token, decrypt_email

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
                       s.slug AS specialty_slug, s.name AS specialty_name
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
    }


# ---------------------------------------------------------------------------
# GET /articles — Articles APPROVED paginés
# ---------------------------------------------------------------------------

def _build_audience_clause(audience: str | None, slug: str | None):
    """Return (where_clause, params_tuple) for audience filtering."""
    if slug == "pharmacien":
        # Pharmaciens voient : PHARMACIENS + prescripteur-type (médicaments) + leur slug
        return (
            "(i.audience = 'PHARMACIENS'"
            " OR i.specialty_slug = 'pharmacien'"
            " OR i.type_praticien = 'prescripteur')",
            (),
        )
    elif slug:
        return "i.specialty_slug = %s", (slug,)
    else:
        return "i.audience = 'SPECIALITE'", ()


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
    source_type: Optional[str] = Query(default=None, description="reglementaire | recommandation | therapeutique | formation"),
    user_id: str = Depends(_get_current_user_id),
):
    # Utiliser la spécialité demandée si fournie, sinon celle de l'utilisateur
    slug = specialty if specialty else _get_user_specialty_slug(user_id)
    aud_clause, aud_params = _build_audience_clause(audience, slug)

    # Build extra WHERE fragments
    extra_clauses: list[str] = []
    extra_params: list[Any] = []

    # Filtrage croisé type_praticien × spécialité
    # Les items sans type_praticien (NULL) passent toujours (rétrocompatibilité).
    if slug in _INTERVENTIONAL_SLUGS:
        # Chirurgiens/anesthésistes : exclure articles prescripteurs sauf score très élevé (≥ 9)
        extra_clauses.append(
            "(i.type_praticien IS NULL"
            " OR i.type_praticien != 'prescripteur'"
            " OR i.score_density >= 9)"
        )
    elif slug in _PRESCRIPTEUR_SLUGS:
        # Prescripteurs : exclure articles interventionnels
        extra_clauses.append(
            "(i.type_praticien IS NULL OR i.type_praticien != 'interventionnel')"
        )

    # Filtre source_type (reglementaire | recommandation | therapeutique | formation)
    _VALID_SOURCE_TYPES = {"reglementaire", "recommandation", "therapeutique", "formation"}
    if source_type and source_type in _VALID_SOURCE_TYPES:
        extra_clauses.append("i.source_type = %s")
        extra_params.append(source_type)

    # Full-text search (ILIKE) — métacaractères LIKE échappés pour éviter un full-scan forcé
    if search and search.strip():
        _s = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{_s}%"
        extra_clauses.append(
            "(c.title_raw ILIKE %s ESCAPE '\\\\' "
            "OR i.tri_json->>'titre_court' ILIKE %s ESCAPE '\\\\' "
            "OR i.tri_json->>'resume' ILIKE %s ESCAPE '\\\\')"
        )
        extra_params.extend([pattern, pattern, pattern])

    # Date range filter — from_date/to_date take priority over month
    if from_date:
        extra_clauses.append("c.official_date >= %s")
        extra_params.append(from_date)
        if to_date:
            extra_clauses.append("c.official_date <= %s")
            extra_params.append(to_date)
    elif month and len(month) == 7:
        # Legacy exact-month filter (used by archives)
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

    extra_where = (" AND " + " AND ".join(extra_clauses)) if extra_clauses else ""
    all_params = (*aud_params, *extra_params)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT COUNT(*) FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND {aud_clause}{extra_where}
            """, all_params)
            total = cur.fetchone()[0]

            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       i.tri_json, i.lecture_json, i.published_at,
                       c.title_raw, c.official_url, c.official_date::text,
                       i.categorie, i.source_type
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND {aud_clause}{extra_where}
                ORDER BY i.score_density DESC, c.official_date DESC
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
    user_id: str = Depends(_get_current_user_id),
):
    date_clause = ""
    date_params: list[Any] = []
    if from_date:
        date_clause += " AND c.official_date >= %s"
        date_params.append(from_date)
    if to_date:
        date_clause += " AND c.official_date <= %s"
        date_params.append(to_date)

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Count per specialty (non-transversal), filtered by date range
            cur.execute(f"""
                SELECT i.specialty_slug, COUNT(*)
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND i.audience != 'TRANSVERSAL_LIBERAL'
                  AND i.specialty_slug IS NOT NULL
                  {date_clause}
                GROUP BY i.specialty_slug;
            """, date_params)
            per_spec = {row[0]: row[1] for row in cur.fetchall()}

    return {
        "per_specialty": per_spec,
    }


# ---------------------------------------------------------------------------
# GET /articles/months — Liste des mois avec nombre d'articles
# ---------------------------------------------------------------------------

@router.get("/articles/months")
def article_months(
    specialty: Optional[str] = Query(default=None),
    audience: Optional[str] = Query(default=None),
    user_id: str = Depends(_get_current_user_id),
):
    slug = specialty if specialty else _get_user_specialty_slug(user_id)
    aud_clause, aud_params = _build_audience_clause(audience, slug)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT to_char(c.official_date, 'YYYY-MM') AS month, COUNT(*)
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND COALESCE(i.score_density, 0) >= 3
                  AND c.official_date IS NOT NULL
                  AND {aud_clause}
                GROUP BY month
                ORDER BY month DESC;
            """, aud_params)
            rows = cur.fetchall()

    return {"months": [{"month": r[0], "count": r[1]} for r in rows]}


# ---------------------------------------------------------------------------
# GET /articles/{item_id} — Détail article
# ---------------------------------------------------------------------------

@router.get("/articles/{item_id}")
def get_article(
    item_id: str,
    user_id: str = Depends(_get_current_user_id),
):
    slug = _get_user_specialty_slug(user_id)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       i.tri_json, i.lecture_json, i.published_at,
                       c.title_raw, c.official_url, c.official_date::text, c.content_raw
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
    }


# ---------------------------------------------------------------------------
# GET /favorites — Liste des item_id favoris de l'utilisateur connecté
# ---------------------------------------------------------------------------

@router.get("/favorites")
def list_favorites(user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT item_id FROM favorites WHERE user_id = %s;",
                (user_id,),
            )
            rows = cur.fetchall()
    return {"item_ids": [str(r[0]) for r in rows]}


# ---------------------------------------------------------------------------
# POST /favorites/{item_id} — Ajoute un favori
# ---------------------------------------------------------------------------

@router.post("/favorites/{item_id}")
def add_favorite(item_id: str, user_id: str = Depends(_get_current_user_id)):
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
def remove_favorite(item_id: str, user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM favorites WHERE user_id = %s AND item_id = %s;",
                (user_id, item_id),
            )
    return {"status": "removed"}


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
<body style="margin:0;padding:0;background-color:#f6f5f2;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">

<!-- Fond global -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background-color:#f6f5f2;" bgcolor="#f6f5f2">
<tr><td align="center" style="padding:40px 16px;">

<!-- Container 600px -->
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
       style="max-width:600px;width:100%;background-color:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e4e0d8;"
       bgcolor="#ffffff">

<!-- Header avec logo texte -->
<tr>
<td align="center" style="padding:36px 40px 24px;border-bottom:1px solid #e4e0d8;background-color:#ffffff;" bgcolor="#ffffff">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td style="width:8px;height:8px;background-color:#1f9478;border-radius:50;" bgcolor="#1f9478">&nbsp;</td>
    <td style="padding-left:10px;">
      <span style="font-family:Georgia,'Times New Roman',serif;font-size:24px;font-weight:400;color:#1a1814;letter-spacing:-0.3px;">
        <em style="font-style:italic;">Med</em>News
      </span>
    </td>
  </tr>
  </table>
  <p style="margin:8px 0 0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:11px;color:#bcb6ac;letter-spacing:1.5px;text-transform:uppercase;">
    Veille r&eacute;glementaire m&eacute;dicale
  </p>
</td>
</tr>

<!-- Corps principal -->
<tr>
<td style="padding:40px 44px;background-color:#ffffff;" bgcolor="#ffffff">

  <!-- Titre -->
  <h1 style="margin:0 0 16px;font-family:Georgia,'Times New Roman',serif;font-size:26px;font-weight:400;color:#1a1814;line-height:1.3;">
    Bienvenue sur <em style="color:#1f9478;font-style:italic;">MedNews</em>
  </h1>

  <!-- Texte -->
  <p style="margin:0 0 8px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;font-weight:300;color:#4a4540;line-height:1.7;">
    Votre compte a bien &eacute;t&eacute; cr&eacute;&eacute;. Pour acc&eacute;der &agrave; votre espace de veille
    r&eacute;glementaire, validez votre adresse email en cliquant sur le bouton ci-dessous.
  </p>
  <p style="margin:0 0 32px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:13px;font-weight:300;color:#9a9288;line-height:1.6;">
    Ce lien expire dans 24&nbsp;heures.
  </p>

  <!-- Bouton CTA -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto 24px;">
  <tr>
    <td align="center" style="background-color:#1f9478;border-radius:8px;" bgcolor="#1f9478">
      <!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" href="{verify_url}" style="height:48px;width:260px;v-text-anchor:middle;" arcsize="17%" fillcolor="#1f9478" stroke="f"><v:textbox inset="0,0,0,0"><center><![endif]-->
      <a href="{verify_url}"
         target="_blank"
         style="display:inline-block;padding:14px 36px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px;background-color:#1f9478;mso-padding-alt:14px 36px;">
        Valider mon compte &rarr;
      </a>
      <!--[if mso]></center></v:textbox></v:roundrect><![endif]-->
    </td>
  </tr>
  </table>

  <!-- Lien de secours -->
  <p style="margin:0 0 0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:12px;color:#9a9288;line-height:1.6;text-align:center;">
    Le bouton ne fonctionne pas&nbsp;? Copiez ce lien dans votre navigateur&nbsp;:<br>
    <a href="{verify_url}" style="color:#1f9478;text-decoration:underline;word-break:break-all;font-size:11px;">
      {verify_url}
    </a>
  </p>

</td>
</tr>

<!-- Séparateur -->
<tr>
<td style="padding:0 44px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr><td style="border-top:1px solid #e4e0d8;font-size:1px;line-height:1px;" height="1">&nbsp;</td></tr>
  </table>
</td>
</tr>

<!-- Footer -->
<tr>
<td style="padding:24px 44px 32px;background-color:#ffffff;" bgcolor="#ffffff">
  <p style="margin:0;font-family:'Courier New',Courier,monospace;font-size:10px;color:#bcb6ac;line-height:2;text-align:center;letter-spacing:0.3px;">
    MedNews &mdash; Veille r&eacute;glementaire pour m&eacute;decins lib&eacute;raux<br>
    &copy; 2026 MedNews. Tous droits r&eacute;serv&eacute;s.<br>
    <span style="color:#9a9288;">Cet email a &eacute;t&eacute; envoy&eacute; automatiquement, merci de ne pas y r&eacute;pondre.</span>
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


def send_verification_email(email: str, raw_token: str) -> None:
    """Envoie l'email de vérification."""
    from app.mailer import send_email

    base_url = os.environ.get("BASE_URL", "").rstrip("/")
    if not base_url:
        logger.warning(
            "BASE_URL non défini — les liens de vérification email "
            "pointeront vers une URL vide. Définir BASE_URL en production."
        )
        base_url = "http://localhost:8000"
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

    try:
        result = send_email(email, subject, html, plain)
        if not result.success:
            logger.error("Échec envoi email vérification à %s : %s", email[:3] + "***", result.error)
        else:
            logger.info("Email de vérification envoyé à %s", email[:3] + "***")
    except Exception as e:
        logger.error("Exception envoi email vérification: %s", e)


@router.post("/auth/verify-email")
def verify_email(payload: VerifyEmailPayload):
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

    return {"ok": True, "message": "Email vérifié avec succès"}


# ---------------------------------------------------------------------------
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


@router.patch("/me/preferences")
def update_preferences(payload: PreferencesUpdate, user_id: str = Depends(_get_current_user_id)):
    fields: list[str] = []
    values: list = []
    if payload.notif_newsletter is not None:
        fields.append("notif_newsletter = %s")
        values.append(payload.notif_newsletter)
    if payload.notif_urgent is not None:
        fields.append("notif_urgent = %s")
        values.append(payload.notif_urgent)
    if payload.newsletter_frequency is not None:
        fields.append("newsletter_frequency = %s")
        values.append(payload.newsletter_frequency)
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
    send_verification_email(email, raw_token)

    return {"ok": True, "message": "Email de vérification envoyé"}
