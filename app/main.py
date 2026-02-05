from app.auth_routes import router as auth_router

import os
import json
import hashlib
import binascii
from datetime import date
from typing import Optional, Any

import psycopg
from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr

from app.db import get_conn
from app.security import bearer_scheme, decode_access_token

# OPTIONAL migrations import (avoid crashing if file missing)
try:
    from app.migrations import run_migrations  # type: ignore
except Exception:
    run_migrations = None  # type: ignore

# PISTE OAuth client
from app.piste_client import get_piste_token

# OPTIONAL: piste_post if you have it (recommended)
try:
    from app.piste_client import piste_post  # type: ignore
except Exception:
    piste_post = None  # type: ignore


app = FastAPI()
app.include_router(auth_router)

DB_INIT_SECRET = os.environ.get("DB_INIT_SECRET")
MIGRATE_SECRET = os.environ.get("MIGRATE_SECRET")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")  # <-- add this in Render + .env

# In prod: set ALLOW_SIGNUP=false on Render
ALLOW_SIGNUP = os.environ.get("ALLOW_SIGNUP", "false").strip().lower() == "true"

INIT_SQL = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- specialties
CREATE TABLE IF NOT EXISTS specialties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL
);

-- users
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_lookup BYTEA NOT NULL UNIQUE,
  email_ciphertext BYTEA NOT NULL,
  password_hash TEXT NOT NULL,
  specialty_id UUID REFERENCES specialties(id),
  email_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- migration: add admin role
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_users_specialty_id ON users (specialty_id);

-- refresh tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

-- migration: rotation link (no FK to keep init idempotent)
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


def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) < 8:
        raise HTTPException(status_code=400, detail="password too short")

    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, 100_000)
    return binascii.hexlify(salt + dk).decode("ascii")


def _exec_sql_block(cur, sql_block: str) -> None:
    """
    Execute a SQL block containing multiple statements.
    OK for our simple init SQL (no $$ blocks).
    """
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
# Auth dependency
# ======================

def get_current_user_id(creds=Depends(bearer_scheme)) -> str:
    payload = decode_access_token(creds.credentials)
    return payload["sub"]


# ======================
# Models
# ======================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    specialty_slug: str | None = None


# ======================
# Routes
# ======================

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
        raise HTTPException(status_code=501, detail="migrations not installed in this build")

    try:
        n, files = run_migrations()
        return {"ok": True, "applied": n, "files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"migration failed: {type(e).__name__}")


@app.post("/admin/piste/token-test")
def piste_token_test(request: Request):
    """
    Simple sanity check: can the backend obtain an OAuth token from PISTE?
    Protected by ADMIN_SECRET.
    """
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)

    try:
        tok = get_piste_token()
        return {"ok": True, "token_preview": tok[:12] + "..."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"piste oauth failed: {type(e).__name__}")


@app.post("/admin/legifrance/scan")
def admin_legifrance_scan(
    request: Request,
    nb_jo: int = 30,
    page_size: int = 100,
):
    """
    Scan Légifrance (JO / JORF) via PISTE and insert into candidates table
    (schema defined in 010_pipeline_candidates_items.sql).
    Protected by ADMIN_SECRET.
    """
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)

    if piste_post is None:
        # You likely have get_piste_token only; add piste_post in app/piste_client.py
        raise HTTPException(status_code=501, detail="piste_post not installed in this build")

    source = "legifrance_jorf"

    # 1) derniers conteneurs JO
    last = piste_post("/consult/lastNJo", {"nbElement": nb_jo})

    cont_ids: list[str] = []
    items: list[Any] = []

    if isinstance(last, dict):
        items = last.get("results") or last.get("list") or last.get("jorfConts") or []
    elif isinstance(last, list):
        items = last

    if isinstance(items, list):
        for x in items:
            if isinstance(x, str) and x.startswith("JORFCONT"):
                cont_ids.append(x)
            elif isinstance(x, dict):
                cid = x.get("id") or x.get("jorfContId")
                if isinstance(cid, str) and cid.startswith("JORFCONT"):
                    cont_ids.append(cid)

    inserted = 0
    duplicates = 0
    skipped_no_date = 0
    errors = 0

    for cont_id in cont_ids:
        cont = piste_post(
            "/consult/jorfCont",
            {
                "highlightActivated": False,
                "id": cont_id,
                "pageNumber": 1,
                "pageSize": page_size,
            },
        )

        cont_items: list[Any] = []
        if isinstance(cont, dict):
            cont_items = cont.get("results") or cont.get("list") or cont.get("texts") or []
        elif isinstance(cont, list):
            cont_items = cont

        text_ids: list[str] = []
        if isinstance(cont_items, list):
            for it in cont_items:
                if isinstance(it, str) and it.startswith("JORFTEXT"):
                    text_ids.append(it)
                elif isinstance(it, dict):
                    tid = it.get("id") or it.get("jorfTextId") or it.get("jorfText") or it.get("textId")
                    if isinstance(tid, str) and tid.startswith("JORFTEXT"):
                        text_ids.append(tid)

        for tid in text_ids:
            try:
                detail = piste_post("/consult/jorf", {"highlightActivated": False, "id": tid})
            except Exception:
                errors += 1
                continue

            title_raw = None
            pdf_url = None
            official_date = None
            content_raw = None

            if isinstance(detail, dict):
                title_raw = detail.get("title") or detail.get("titre") or detail.get("norTitre")
                pdf_url = detail.get("pdfUrl") or detail.get("pdf") or detail.get("pdf_url")

                # publication date (JO)
                official_date = (
                    _parse_iso_date10(detail.get("datePublication"))
                    or _parse_iso_date10(detail.get("datePubli"))
                    or _parse_iso_date10(detail.get("publicationDate"))
                )

                # optional raw content if present
                content_raw = detail.get("text") or detail.get("texte") or detail.get("content")

            if official_date is None:
                skipped_no_date += 1
                continue

            official_url = _legifrance_jorf_url(tid)
            dedupe_key = _sha256_hex(f"{source}|{tid}")
            raw_sha256 = _json_sha256(detail)

            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO candidates
                          (source, official_url, official_date, title_raw, pdf_url, content_raw, raw_sha256, dedupe_key)
                        VALUES
                          (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (dedupe_key) DO NOTHING;
                        """,
                        (source, official_url, official_date, title_raw, pdf_url, content_raw, raw_sha256, dedupe_key),
                    )
                    if cur.rowcount == 1:
                        inserted += 1
                    else:
                        duplicates += 1

    return {
        "ok": True,
        "containers": len(cont_ids),
        "inserted": inserted,
        "duplicates": duplicates,
        "skipped_no_date": skipped_no_date,
        "errors": errors,
    }


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
    email_ciphertext = email_norm.encode("utf-8")  # MVP: clair pour l'instant
    password_hash = hash_password(payload.password)

    with get_conn() as conn:
        with conn.cursor() as cur:
            specialty_id = None

            if payload.specialty_slug:
                cur.execute("SELECT id FROM specialties WHERE slug = %s;", (payload.specialty_slug,))
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

    return {"id": str(user_id), "created_at": created_at.isoformat()}


@app.get("/me")
def me(user_id: str = Depends(get_current_user_id)):
    return {"user_id": user_id}


@app.get("/_version")
def version():
    return {"commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")}
