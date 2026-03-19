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
from app.scheduler import lifespan, job_collect_and_analyse, job_send_newsletters
from app.sources_routes import router as sources_router

import psycopg
from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr

from app.db import get_conn
from app.security import hash_password, encrypt_email

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


_IFRAME_ALLOWED_PATHS = {"/newsletter-demo", "/portal-demo"}

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"  # Désactivé : CSP est plus sûr
        if request.url.path in _IFRAME_ALLOWED_PATHS:
            # Allow these pages to be embedded in iframes from the same origin
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com https://fonts.gstatic.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https://fonts.gstatic.com; "
                "connect-src 'self'; "
                "frame-ancestors 'self';"
            )
        else:
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
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

app.include_router(auth_router)
app.include_router(piste_router)
app.include_router(llm_router)
app.include_router(sources_router)
app.include_router(portal_router)

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_FRONT_DIR = os.path.join(os.path.dirname(__file__), "..", "med-news-front")

# Serve static assets (screenshots, images, etc.)
_screenshots_dir = os.path.join(_FRONT_DIR, "screenshots")
if os.path.isdir(_screenshots_dir):
    app.mount("/screenshots", StaticFiles(directory=_screenshots_dir), name="screenshots")

_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"}

@app.get("/")
def serve_landing():
    return FileResponse(os.path.join(_FRONT_DIR, "index.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/review")
def serve_review():
    return FileResponse(os.path.join(_FRONT_DIR, "review.html"), media_type="text/html", headers=_NO_CACHE)

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

@app.get("/settings")
def serve_settings():
    return FileResponse(os.path.join(_FRONT_DIR, "settings.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/newsletter-demo")
def serve_newsletter_demo():
    return FileResponse(os.path.join(_FRONT_DIR, "newsletter-demo.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/portal-demo")
def serve_portal_demo():
    return FileResponse(os.path.join(_FRONT_DIR, "portal.html"), media_type="text/html", headers=_NO_CACHE)

@app.get("/shared.js")
def serve_shared_js():
    return FileResponse(os.path.join(_FRONT_DIR, "shared.js"), media_type="application/javascript", headers=_NO_CACHE)


DB_INIT_SECRET = os.environ.get("DB_INIT_SECRET")
MIGRATE_SECRET = os.environ.get("MIGRATE_SECRET")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")

ALLOW_SIGNUP = os.environ.get("ALLOW_SIGNUP", "false").strip().lower() == "true"

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

@app.post("/admin/scheduler/run-collect")
def admin_run_collect(request: Request):
    """Déclenche manuellement collecte JORF + analyse LLM."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        job_collect_and_analyse()
        return {"ok": True, "job": "collect_and_analyse"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/scheduler/run-send")
def admin_run_send(request: Request):
    """Déclenche manuellement l'envoi des newsletters."""
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    try:
        job_send_newsletters()
        return {"ok": True, "job": "send_newsletters"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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


@app.post("/users", status_code=201)
def create_user(payload: UserCreate):
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
                    INSERT INTO users (email_lookup, email_ciphertext, password_hash, specialty_id)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, created_at;
                    """,
                    (email_lookup, email_ciphertext, password_hash, specialty_id),
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
            from app.portal_routes import generate_verification_token, send_verification_email
            raw_token = generate_verification_token(str(user_id))
            send_verification_email(email_norm, raw_token)
        except Exception:
            pass  # Don't block signup if email fails

    return {"id": str(user_id), "created_at": created_at.isoformat()}



@app.get("/_version")
def version():
    return {"commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")}
