from app.auth_routes import router as auth_router

import os
import hashlib
import binascii

import psycopg
from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr

from app.db import get_conn
from app.security import bearer_scheme, decode_access_token

app = FastAPI()
app.include_router(auth_router)

DB_INIT_SECRET = os.environ.get("DB_INIT_SECRET")

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
    secret = request.headers.get("x-init-secret")
    if not DB_INIT_SECRET or secret != DB_INIT_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(INIT_SQL)
        return {"ok": True}
    except Exception:
        raise HTTPException(status_code=500, detail="db init failed")


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
                cur.execute(
                    "SELECT id FROM specialties WHERE slug = %s;",
                    (payload.specialty_slug,),
                )
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


# Protected route (Bearer test)
@app.get("/me")
def me(user_id: str = Depends(get_current_user_id)):
    return {"user_id": user_id}


@app.get("/_version")
def version():
    return {"commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")}
