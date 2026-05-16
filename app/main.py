from dotenv import load_dotenv
load_dotenv()

from app.auth_routes import router as auth_router

import os
import json
import hashlib
from datetime import date
from typing import Optional, Any
from app.piste_routes import router as piste_router
from app.llm_routes import router as llm_router
from app.scheduler import (
    lifespan,
    job_collect_regulation,
    job_collect_recommendations,
    job_try_send_regulation,
    job_try_send_recommendations,
)
from app.sources_routes import router as sources_router

import psycopg
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Depends, UploadFile, Form, File
from pydantic import BaseModel, EmailStr

from app.db import get_conn
from app.security import hash_password, encrypt_email, require_admin as _require_admin, make_signup_token, verify_signup_token

try:
    from app.migrations import run_migrations  # type: ignore
except Exception:
    run_migrations = None  # type: ignore

from app.piste_client import get_piste_token

try:
    from app.piste_client import piste_post  # type: ignore
except Exception:
    piste_post = None  # type: ignore


from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

app = FastAPI(lifespan=lifespan)


_IFRAME_ALLOWED_PATHS = {"/newsletter-demo", "/newsletter-preview", "/portal-demo", "/portal"}

# CSP commune : autorise Google Fonts + Lucide CDN (utilisés par toutes les pages front)
_CSP_SCRIPT = "script-src 'self' 'unsafe-inline' https://unpkg.com"
_CSP_STYLE  = "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com"
_CSP_FONT   = "font-src 'self' data: https://fonts.gstatic.com"
_CSP_COMMON = (
    f"default-src 'self'; "
    f"{_CSP_SCRIPT}; "
    f"{_CSP_STYLE}; "
    "img-src 'self' data: blob: https:; "
    f"{_CSP_FONT}; "
    "connect-src 'self'"
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"  # Désactivé : CSP est plus sûr
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path in _IFRAME_ALLOWED_PATHS:
            response.headers["Content-Security-Policy"] = (
                f"{_CSP_COMMON}; frame-ancestors 'self';"
            )
        else:
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = (
                f"{_CSP_COMMON}; frame-ancestors 'none';"
            )
        return response


app.add_middleware(SecurityHeadersMiddleware)

_CORS_ORIGINS_RAW = os.environ.get("CORS_ORIGINS", "")
_CORS_ORIGINS: list[str] = (
    [o.strip() for o in _CORS_ORIGINS_RAW.split(",") if o.strip()]
    if _CORS_ORIGINS_RAW.strip()
    else ["http://localhost:3000", "http://localhost:8080"]
)

import logging as _logging
_startup_logger = _logging.getLogger(__name__)
if not _CORS_ORIGINS_RAW.strip() and os.environ.get("SCHEDULER_ENABLED", "").lower() == "true":
    _startup_logger.warning(
        "CORS_ORIGINS non défini en production ! "
        "Les origines par défaut (localhost) seront utilisées."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.portal_routes import router as portal_router
from app.demo_routes import router as demo_router
from app.billing_routes import router as billing_router

app.include_router(auth_router)
app.include_router(piste_router)
app.include_router(llm_router)
app.include_router(sources_router)
app.include_router(portal_router)
app.include_router(demo_router)
app.include_router(billing_router)

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_FRONT_DIR = os.path.join(os.path.dirname(__file__), "..", "med-news-front")

# Serve static assets (screenshots, images, etc.)
_screenshots_dir = os.path.join(_FRONT_DIR, "screenshots")
if os.path.isdir(_screenshots_dir):
    app.mount("/screenshots", StaticFiles(directory=_screenshots_dir), name="screenshots")

_img_dir = os.path.join(_FRONT_DIR, "img")
if os.path.isdir(_img_dir):
    app.mount("/img", StaticFiles(directory=_img_dir), name="img")

_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"}

@app.api_route("/", methods=["GET", "HEAD"])
def serve_landing():
    return FileResponse(os.path.join(_FRONT_DIR, "index.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/review")
def serve_review():
    return FileResponse(os.path.join(_FRONT_DIR, "review.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/signalements")
def serve_signalements():
    return FileResponse(os.path.join(_FRONT_DIR, "signalements.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/etudiants")
def serve_etudiants():
    return FileResponse(os.path.join(_FRONT_DIR, "etudiants.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/login")
def serve_login():
    return FileResponse(os.path.join(_FRONT_DIR, "login.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/signup")
def serve_signup():
    return FileResponse(os.path.join(_FRONT_DIR, "signup.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/portal")
def serve_portal():
    return FileResponse(os.path.join(_FRONT_DIR, "portal.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/verify-email")
def serve_verify_email():
    return FileResponse(os.path.join(_FRONT_DIR, "verify-email.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/archives")
def serve_archives():
    return FileResponse(os.path.join(_FRONT_DIR, "archives.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/users")
def serve_users():
    return FileResponse(os.path.join(_FRONT_DIR, "users.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/newsletter")
def serve_newsletter_admin():
    return FileResponse(os.path.join(_FRONT_DIR, "newsletter.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/settings")
def serve_settings():
    return FileResponse(os.path.join(_FRONT_DIR, "settings.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/newsletter-demo")
def serve_newsletter_demo():
    return FileResponse(os.path.join(_FRONT_DIR, "newsletter-demo.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/newsletter-preview")
def newsletter_preview(specialty: str = "chirurgie-vasculaire"):
    from fastapi.responses import HTMLResponse
    from datetime import date as _date
    from app.newsletter_builder import build_newsletter
    from app.demo_routes import _fetch_demo_articles, _latest_active_month
    from_date, to_date = _latest_active_month(specialty)
    to_d = _date.fromisoformat(to_date)
    items = _fetch_demo_articles(specialty, from_date, to_date)
    _, html, _ = build_newsletter(specialty, items, emission_date=to_d)
    if not html:
        html = "<html><body style='font-family:sans-serif;padding:40px;color:#666'>Aucun article disponible pour cette période.</body></html>"
    return HTMLResponse(content=html, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/portal-demo")
def serve_portal_demo():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/portal?demo=1", status_code=302)

@app.get("/shared.js")
def serve_shared_js():
    return FileResponse(os.path.join(_FRONT_DIR, "shared.js"), media_type="application/javascript", headers=_NO_CACHE)

@app.get("/banner.js")
def serve_banner_js():
    return FileResponse(os.path.join(_FRONT_DIR, "banner.js"), media_type="application/javascript", headers=_NO_CACHE)

@app.get("/native-bridge.js")
def serve_native_bridge_js():
    return FileResponse(os.path.join(_FRONT_DIR, "native-bridge.js"), media_type="application/javascript", headers=_NO_CACHE)

@app.get("/googleeb1fd567485e9181.html")
def serve_google_verification():
    return FileResponse(os.path.join(_FRONT_DIR, "googleeb1fd567485e9181.html"), media_type="text/html")

@app.get("/sitemap.xml")
def serve_sitemap():
    return FileResponse(os.path.join(_FRONT_DIR, "sitemap.xml"), media_type="application/xml")

@app.get("/cgv")
def serve_cgv():
    return FileResponse(os.path.join(_FRONT_DIR, "cgv.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/mentions-legales")
def serve_mentions_legales():
    return FileResponse(os.path.join(_FRONT_DIR, "mentions-legales.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/politique-confidentialite")
def serve_politique_confidentialite():
    return FileResponse(os.path.join(_FRONT_DIR, "politique-confidentialite.html"), media_type="text/html", headers=_NO_CACHE)


DB_INIT_SECRET = os.environ.get("DB_INIT_SECRET")
MIGRATE_SECRET = os.environ.get("MIGRATE_SECRET")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")

ALLOW_SIGNUP = os.environ.get("ALLOW_SIGNUP", "true").strip().lower() == "true"

INIT_SQL = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS specialties (
  slug TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_lookup BYTEA NOT NULL UNIQUE,
  email_ciphertext BYTEA NOT NULL,
  password_hash TEXT NOT NULL,
  specialty_id TEXT REFERENCES specialties(slug),
  email_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_users_specialty_id ON users (specialty_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

ALTER TABLE refresh_tokens
  ADD COLUMN IF NOT EXISTS replaced_by UUID;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
"""


# ======================
# Helpers
# ======================

def normalize_email(email: str) -> str:
    return email.strip().lower()


def email_lookup_hash(email_norm: str) -> bytes:
    return hashlib.sha256(email_norm.encode("utf-8")).digest()


def _exec_sql_block(cur, sql_block: str) -> None:
    statements = [s.strip() for s in sql_block.split(";") if s.strip()]
    for stmt in statements:
        cur.execute(stmt + ";")


def _require_secret(request: Request, header_name: str, expected: Optional[str]) -> None:
    secret = request.headers.get(header_name)
    if not expected or secret != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _json_sha256(obj: Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _sha256_hex(raw)


def _legifrance_jorf_url(jorftext_id: str) -> str:
    return f"https://www.legifrance.gouv.fr/jorf/id/{jorftext_id}"


def _parse_iso_date10(v: Any) -> Optional[date]:
    if isinstance(v, str) and len(v) >= 10:
        try:
            return date.fromisoformat(v[:10])
        except Exception:
            return None
    return None


# ======================
# Models
# ======================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    specialty_slug: str | None = None
    first_name: str | None = None
    last_name: str | None = None


# ======================
# Routes système
# ======================

@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "ok"}

@app.get("/health/db")
def health_db():
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select 1;")
        return {"ok": True}
    except Exception:
        raise HTTPException(status_code=500, detail="db connection failed")


@app.post("/admin/init-db")
async def init_db(request: Request):
    _require_secret(request, "x-init-secret", DB_INIT_SECRET)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                _exec_sql_block(cur, INIT_SQL)
        return {"ok": True}
    except Exception:
        raise HTTPException(status_code=500, detail="db init failed")


@app.post("/admin/migrate")
async def admin_migrate(request: Request):
    _require_secret(request, "x-migrate-secret", MIGRATE_SECRET)
    if run_migrations is None:
        raise HTTPException(status_code=501, detail="migrations not installed")
    try:
        n, files = run_migrations()
        return {"ok": True, "applied": n, "files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"migration failed: {type(e).__name__}")


# ======================
# Routes scheduler (déclenchement manuel)
# ======================

@app.get("/admin/piste/debug")
def admin_piste_debug(request: Request):
    """Debug : vérifie les env vars PISTE vues par le process Render."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    import os
    all_keys = sorted(os.environ.keys())
    piste_adjacent = [repr(k) for k in all_keys if "PI" in k.upper() or "LF_" in k.upper() or "LEGI" in k.upper()]
    anthropic_ok = bool(os.environ.get("ANTHROPIC_API_KEY"))
    database_ok = bool(os.environ.get("DATABASE_URL"))
    return {
        "total_env_vars": len(os.environ),
        "piste_adjacent_keys": piste_adjacent,
        "anthropic_set": anthropic_ok,
        "database_set": database_ok,
    }


@app.post("/admin/scheduler/run-collect")
def admin_run_collect(request: Request):
    """Déclenche manuellement collecte réglementation + recommandations."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        job_collect_regulation()
        job_collect_recommendations()
        return {"ok": True, "job": "collect_regulation+recommendations"}
    except Exception as e:
        _startup_logger.exception("Erreur admin run-collect")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/scheduler/run-collect-regulation")
def admin_run_collect_regulation(request: Request):
    """Déclenche manuellement la collecte réglementation uniquement
    (JORF, KALI, LEGI, CIRCULAIRES, ANSM, BO Social, CNOM, ameli.fr, CARMF, CARPIMKO)."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        report = job_collect_regulation()
        return {"ok": True, "job": "collect_regulation", "report": report}
    except Exception as e:
        _startup_logger.exception("Erreur admin run-collect-regulation")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/collect/cnom")
def admin_collect_cnom(request: Request, days: int = 180):
    """Scrape le site CNOM (actualités, communiqués, fiches pratiques).
    Remplace le flux RSS CNOM qui retourne 0 entrées depuis 2026."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        from app.web_scraper import collect_cnom
        result = collect_cnom(days=days)
        return {"ok": True, **result}
    except Exception as e:
        _startup_logger.exception("Erreur collect CNOM")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/collect/ameli-medecin")
def admin_collect_ameli_medecin(request: Request, days: int = 180):
    """Scrape ameli.fr/medecin/actualites (convention médicale, téléconsultation, CCAM…)."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        from app.web_scraper import collect_ameli_medecin
        result = collect_ameli_medecin(days=days)
        return {"ok": True, **result}
    except Exception as e:
        _startup_logger.exception("Erreur collect ameli.fr médecin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/collect/carmf")
def admin_collect_carmf(request: Request, days: int = 180):
    """Scrape le site CARMF (PSS, cotisations, ASV, retraite médecins libéraux)."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        from app.web_scraper import collect_carmf
        result = collect_carmf(days=days)
        return {"ok": True, **result}
    except Exception as e:
        _startup_logger.exception("Erreur collect CARMF")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/collect/carpimko")
def admin_collect_carpimko(request: Request, days: int = 180):
    """Scrape le site CARPIMKO (cotisations, retraite auxiliaires médicaux libéraux)."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        from app.web_scraper import collect_carpimko
        result = collect_carpimko(days=days)
        return {"ok": True, **result}
    except Exception as e:
        _startup_logger.exception("Erreur collect CARPIMKO")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/collect/specialty/{slug}")
def admin_collect_specialty(slug: str, request: Request, days: int = 120):
    """Déclenche la collecte complète (PubMed + RSS + réglementation + recommandations) pour une spécialité."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        from app.db import get_conn
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM specialties WHERE slug = %s", (slug,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail=f"Spécialité inconnue : {slug}")
        from app.scheduler import collect_by_specialty
        report = collect_by_specialty(slug, days=days)
        return {"ok": True, "specialty": slug, "report": report}
    except HTTPException:
        raise
    except Exception as e:
        _startup_logger.exception("Erreur collect specialty %s", slug)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/scheduler/run-send")
def admin_run_send(request: Request):
    """Déclenche manuellement l'envoi des newsletters réglementation + recommandations."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        job_try_send_regulation()
        job_try_send_recommendations()
        return {"ok": True, "job": "send_regulation+recommendations"}
    except Exception as e:
        _startup_logger.exception("Erreur admin run-send")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.post("/admin/process-pending-emails")
def admin_process_pending_emails(request: Request):
    """Traite la queue pending_emails — appelé par le cron GitHub Actions."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    from app.mailer import send_email
    sent, failed, skipped = 0, 0, 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, to_email, subject, html_body, plain_body
                FROM pending_emails
                WHERE sent_at IS NULL AND attempts < max_attempts
                ORDER BY created_at
                LIMIT 50
            """)
            rows = cur.fetchall()
            for row in rows:
                email_id, to_email, subject, html, plain = row
                try:
                    result = send_email(to_email, subject, html, plain)
                    if result.success:
                        cur.execute(
                            "UPDATE pending_emails SET sent_at = now() WHERE id = %s",
                            (email_id,)
                        )
                        sent += 1
                    else:
                        cur.execute(
                            "UPDATE pending_emails SET attempts = attempts + 1, last_error = %s WHERE id = %s",
                            (result.error, email_id)
                        )
                        failed += 1
                        _startup_logger.error("Échec envoi pending email %s : %s", email_id, result.error)
                except Exception as e:
                    cur.execute(
                        "UPDATE pending_emails SET attempts = attempts + 1, last_error = %s WHERE id = %s",
                        (str(e), email_id)
                    )
                    failed += 1
                    _startup_logger.error("Exception pending email %s : %s", email_id, e)
    _startup_logger.info("process-pending-emails : sent=%d failed=%d skipped=%d", sent, failed, skipped)
    return {"ok": True, "sent": sent, "failed": failed}


@app.post("/admin/test-email")
def admin_test_email(request: Request):
    """Teste l'envoi email et retourne le résultat + config active."""
    import os as _os
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    from app.mailer import send_email

    # Déterminer le transport actif
    transport = "none"
    if _os.environ.get("SENDGRID_API_KEY"):
        transport = "sendgrid"
    elif _os.environ.get("SMTP_HOST"):
        transport = f"smtp:{_os.environ.get('SMTP_HOST')}:{_os.environ.get('SMTP_PORT','587')}"

    mail_from = _os.environ.get("MAIL_FROM", "")
    to_email = mail_from  # s'envoie à lui-même

    if not to_email:
        raise HTTPException(status_code=500, detail="MAIL_FROM non défini")

    try:
        result = send_email(
            to_email,
            "MedNews — Test email transport",
            "<p>Test OK depuis Render.</p>",
            "Test OK depuis Render.",
        )
        return {
            "transport": transport,
            "mail_from": mail_from,
            "success": result.success,
            "error": result.error,
        }
    except Exception as e:
        return {
            "transport": transport,
            "mail_from": mail_from,
            "success": False,
            "error": str(e),
        }


# ======================
# Routes utilisateurs
# ======================

@app.get("/specialties")
def list_specialties():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT slug, name FROM specialties ORDER BY name;")
            rows = cur.fetchall()
    return [{"slug": s, "name": n} for (s, n) in rows]


def _try_flush_pending_emails() -> None:
    """Tente d'envoyer les emails en queue immédiatement (best-effort)."""
    from app.mailer import send_email
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, to_email, subject, html_body, plain_body
                FROM pending_emails
                WHERE sent_at IS NULL AND attempts < max_attempts
                ORDER BY created_at
                LIMIT 10
            """)
            rows = cur.fetchall()
            for email_id, to_email, subject, html, plain in rows:
                try:
                    result = send_email(to_email, subject, html, plain)
                    if result.success:
                        cur.execute(
                            "UPDATE pending_emails SET sent_at = now() WHERE id = %s",
                            (email_id,)
                        )
                        _startup_logger.info("Email envoyé immédiatement : %s", email_id)
                    else:
                        cur.execute(
                            "UPDATE pending_emails SET attempts = attempts + 1, last_error = %s WHERE id = %s",
                            (result.error, email_id)
                        )
                        _startup_logger.warning("Envoi immédiat échoué (%s) — sera retenté par le cron", result.error)
                except Exception as e:
                    cur.execute(
                        "UPDATE pending_emails SET attempts = attempts + 1, last_error = %s WHERE id = %s",
                        (str(e), email_id)
                    )
                    _startup_logger.warning("Exception envoi immédiat (%s) — sera retenté par le cron", e)


@app.post("/users", status_code=201)
def create_user(payload: UserCreate, background_tasks: BackgroundTasks):
    if not ALLOW_SIGNUP:
        raise HTTPException(status_code=403, detail="signup disabled")
    email_norm = normalize_email(payload.email)
    email_lookup = email_lookup_hash(email_norm)
    email_ciphertext = encrypt_email(email_norm)
    password_hash = hash_password(payload.password)
    with get_conn() as conn:
        with conn.cursor() as cur:
            specialty_id = None
            if payload.specialty_slug:
                cur.execute("SELECT slug FROM specialties WHERE slug = %s;", (payload.specialty_slug,))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=400, detail="unknown specialty_slug")
                specialty_id = row[0]
            try:
                cur.execute(
                    """
                    INSERT INTO users (email_lookup, email_ciphertext, password_hash, specialty_id,
                                       first_name, last_name, trial_ends_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW() + INTERVAL '1 month')
                    RETURNING id, created_at;
                    """,
                    (email_lookup, email_ciphertext, password_hash, specialty_id,
                     payload.first_name or None, payload.last_name or None),
                )
                user_id, created_at = cur.fetchone()
            except psycopg.errors.UniqueViolation:
                raise HTTPException(status_code=409, detail="email already exists")

    # En dev (pas de SMTP/SendGrid fonctionnel) : auto-vérifier
    auto_verify = os.environ.get("AUTO_VERIFY_EMAIL", "false").strip().lower() == "true"
    if auto_verify:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET email_verified_at = now() WHERE id = %s;",
                    (user_id,),
                )
    else:
        try:
            from app.portal_routes import generate_verification_token, queue_verification_email
            raw_token = generate_verification_token(str(user_id))
            queue_verification_email(email_norm, raw_token)
            # Tente l'envoi immédiat en arrière-plan — le cron prend le relais si ça échoue
            background_tasks.add_task(_try_flush_pending_emails)
        except Exception as e:
            _startup_logger.error("Échec mise en queue email vérification pour user %s : %s", user_id, e)

    return {
        "id": str(user_id),
        "created_at": created_at.isoformat(),
        "signup_token": make_signup_token(str(user_id)),
    }



@app.post("/student-request/signup", status_code=201)
async def student_request_signup(
    user_id: str = Form(...),
    signup_token: str = Form(...),
    file: UploadFile = File(...),
):
    """Upload carte étudiante lors de l'inscription (avant vérification email, sans JWT)."""
    if not verify_signup_token(signup_token, user_id):
        raise HTTPException(status_code=403, detail="invalid or expired signup token")

    _ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "application/pdf"}
    _MAX_SIZE = 5 * 1024 * 1024
    if file.content_type not in _ALLOWED_MIME:
        raise HTTPException(status_code=415, detail="Format non supporté (JPEG, PNG, WebP, PDF)")
    data = await file.read()
    if len(data) > _MAX_SIZE:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (max 5 Mo)")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM users WHERE id = %s", (user_id,)
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="user not found")
            cur.execute(
                "SELECT status FROM student_requests WHERE user_id = %s ORDER BY created_at DESC LIMIT 1",
                (user_id,),
            )
            existing = cur.fetchone()
            if existing and existing[0] in ("pending", "approved"):
                raise HTTPException(status_code=409, detail=f"Demande déjà en cours ({existing[0]})")
            cur.execute(
                "INSERT INTO student_requests (user_id, document_data, document_mime) VALUES (%s, %s, %s) RETURNING id",
                (user_id, data, file.content_type),
            )
            req_id = cur.fetchone()[0]
            # Accès limité à 48h en attente de validation admin
            cur.execute(
                "UPDATE users SET trial_ends_at = NOW() + INTERVAL '48 hours' WHERE id = %s",
                (user_id,),
            )
    return {"id": str(req_id), "status": "pending"}


@app.post("/admin/users/{user_id}/verify-email")
def admin_verify_email(user_id: str, request: Request):
    """Force la vérification email d'un compte (admin uniquement — usage test/support)."""
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET email_verified_at = now() WHERE id = %s RETURNING id;",
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"ok": True, "user_id": user_id}


@app.get("/admin/users")
def admin_list_users(request: Request):
    """Liste tous les comptes médecins avec email déchiffré, spécialité et statut."""
    _require_admin(request)
    from app.security import decrypt_email
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email_ciphertext, u.specialty_id,
                       u.email_verified_at, u.created_at, u.is_active, u.is_admin,
                       u.plan, u.trial_ends_at, u.stripe_subscription_id,
                       sr.status AS student_status
                FROM users u
                LEFT JOIN LATERAL (
                    SELECT status FROM student_requests
                    WHERE user_id = u.id ORDER BY created_at DESC LIMIT 1
                ) sr ON true
                ORDER BY u.created_at DESC;
                """
            )
            rows = cur.fetchall()
    users = []
    for r in rows:
        try:
            email = decrypt_email(bytes(r[1]))
        except Exception:
            email = "(chiffrement illisible)"
        users.append({
            "id": str(r[0]),
            "email": email,
            "specialty_id": r[2],
            "email_verified": r[3] is not None,
            "created_at": r[4].isoformat() if r[4] else None,
            "is_active": r[5],
            "is_admin": r[6],
            "plan": r[7],
            "trial_ends_at": r[8].isoformat() if r[8] else None,
            "has_stripe_sub": r[9] is not None,
            "student_status": r[10],
        })
    return {"ok": True, "count": len(users), "users": users}


@app.post("/admin/users/{user_id}/deactivate")
def admin_deactivate_user(user_id: str, request: Request):
    """Désactive un compte médecin (ne peut plus se connecter)."""
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET is_active = FALSE WHERE id = %s AND is_admin = FALSE RETURNING id;",
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found or is admin")
    return {"ok": True, "user_id": user_id, "is_active": False}


@app.post("/admin/users/{user_id}/activate")
def admin_activate_user(user_id: str, request: Request):
    """Réactive un compte médecin désactivé."""
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET is_active = TRUE WHERE id = %s RETURNING id;",
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"ok": True, "user_id": user_id, "is_active": True}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, request: Request):
    """Supprime définitivement un compte médecin (libère l'adresse email)."""
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM users WHERE id = %s AND is_admin = FALSE RETURNING id;",
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found or is admin")
    return {"ok": True, "user_id": user_id, "deleted": True}


@app.get("/admin/reports")
def admin_list_reports(request: Request, limit: int = 100):
    """Liste les signalements praticiens (item_reports) avec titre article et email user."""
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    ir.id,
                    ir.created_at,
                    ir.reason,
                    ir.comment,
                    ir.item_id,
                    i.tri_json->>'titre_court'   AS titre,
                    i.specialty_slug,
                    i.review_status,
                    u.email_ciphertext           AS email_enc
                FROM item_reports ir
                JOIN items i ON i.id = ir.item_id
                LEFT JOIN users u ON u.id = ir.user_id
                ORDER BY ir.created_at DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()

    result = []
    for row in rows:
        rid, created_at, reason, comment, item_id, titre, slug, review_status, email_enc = row
        email = None
        if email_enc:
            try:
                from app.security import decrypt_email
                email = decrypt_email(email_enc)
            except Exception:
                email = "(chiffré)"
        result.append({
            "id": str(rid),
            "created_at": created_at.isoformat() if created_at else None,
            "reason": reason,
            "comment": comment,
            "item_id": str(item_id),
            "titre": titre,
            "specialty_slug": slug,
            "review_status": review_status,
            "user_email": email,
        })
    return {"reports": result, "total": len(result)}


@app.delete("/admin/reports/{report_id}")
def admin_dismiss_report(report_id: str, request: Request):
    """Supprime définitivement un signalement (action 'Ignorer')."""
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM item_reports WHERE id = %s", (report_id,))
        conn.commit()
    return {"ok": True}


@app.post("/admin/send-newsletter-unified")
def admin_send_newsletter_unified(request: Request):
    """Déclenche l'envoi de la newsletter unifiée tous types (régle + reco + innov), fenêtre 3j."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        from app.scheduler import job_send_unified
        job_send_unified()
        return {"ok": True, "job": "send_unified"}
    except Exception as e:
        _startup_logger.exception("Erreur send-newsletter-unified")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@app.get("/_version")
def version():
    return {"commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")}


# ---------------------------------------------------------------------------
# Admin — demandes accès étudiant
# ---------------------------------------------------------------------------

@app.get("/admin/student-requests")
def admin_list_student_requests(request: Request, status: str = "pending"):
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT sr.id, sr.user_id, sr.status, sr.reject_reason,
                       sr.created_at, sr.reviewed_at,
                       u.email_ciphertext, u.first_name, u.last_name
                FROM student_requests sr
                JOIN users u ON u.id = sr.user_id
                WHERE sr.status = %s
                ORDER BY sr.created_at ASC
            """, (status,))
            rows = cur.fetchall()
    from app.security import decrypt_email
    result = []
    for r in rows:
        result.append({
            "id": str(r[0]), "user_id": str(r[1]), "status": r[2],
            "reject_reason": r[3],
            "created_at": r[4].isoformat() if r[4] else None,
            "reviewed_at": r[5].isoformat() if r[5] else None,
            "email": decrypt_email(r[6]),
            "first_name": r[7], "last_name": r[8],
        })
    return {"requests": result, "total": len(result)}


@app.get("/admin/student-requests/{req_id}/document")
def admin_get_student_document(req_id: str, request: Request):
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT document_data, document_mime FROM student_requests WHERE id = %s",
                (req_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    from fastapi.responses import Response
    return Response(content=bytes(row[0]), media_type=row[1])


@app.post("/admin/student-requests/{req_id}/approve")
def admin_approve_student(req_id: str, request: Request):
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id FROM student_requests WHERE id = %s AND status = 'pending'",
                (req_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="demande introuvable ou déjà traitée")
            user_id = row[0]
            cur.execute(
                "UPDATE student_requests SET status='approved', reviewed_at=NOW() WHERE id=%s",
                (req_id,),
            )
            cur.execute(
                "UPDATE users SET plan='student' WHERE id=%s",
                (user_id,),
            )
    return {"ok": True, "user_id": str(user_id), "plan": "student"}


class RejectPayload(BaseModel):
    reason: Optional[str] = None


@app.post("/admin/student-requests/{req_id}/reject")
def admin_reject_student(req_id: str, payload: RejectPayload, request: Request):
    _require_admin(request)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id FROM student_requests WHERE id = %s AND status = 'pending'",
                (req_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="demande introuvable ou déjà traitée")
            cur.execute(
                "UPDATE student_requests SET status='rejected', reject_reason=%s, reviewed_at=NOW() WHERE id=%s",
                (payload.reason, req_id),
            )
    return {"ok": True}
