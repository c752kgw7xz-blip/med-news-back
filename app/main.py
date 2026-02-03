import os
import hashlib
import psycopg
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

app = FastAPI()

# =========================
# Config
# =========================

DB_INIT_SECRET = os.environ.get("DB_INIT_SECRET")

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

# =========================
# SQL init (idempotent)
# =========================

INIT_SQL = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS specialties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_lookup BYTEA NOT NULL UNIQUE,
  email_ciphertext BYTEA NOT NULL,
  password_hash TEXT NOT NULL,
  specialty_id UUID REFERENCES specialties(id),
  email_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_specialty_id ON users (specialty_id);
"""

# =========================
# Helpers
# =========================

def get_conn():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg.connect(database_url)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def email_lookup_hash(email_norm: str) -> bytes:
    # MVP: hash déterministe simple
    return hashlib.sha256(email_norm.encode("utf-8")).digest()


# =========================
# Models
# =========================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    specialty_slug: str | None = None


# =========================
# Routes
# =========================

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
            conn.commit()
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
    email_norm = normalize_email(payload.email)

    # --- password validation (CRUCIAL) ---
    pw_bytes = payload.password.encode("utf-8")

    if len(pw_bytes) < 8:
        raise HTTPException(status_code=400, detail="password too short")

    if len(pw_bytes) > 72:
        raise HTTPException(
            status_code=400,
            detail="password too long (bcrypt limit: 72 bytes)",
        )

    email_lookup = email_lookup_hash(email_norm)
    email_ciphertext = email_norm.encode("utf-8")  # TEMPORAIRE (clair)
    password_hash = pwd_context.hash(payload.password)

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
                    raise HTTPException(
                        status_code=400,
                        detail="unknown specialty_slug",
                    )
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
                raise HTTPException(
                    status_code=409,
                    detail="email already exists",
                )

        conn.commit()

    return {
        "id": str(user_id),
        "created_at": created_at.isoformat(),
    }


@app.get("/_version")
def version():
    return {
        "commit": os.environ.get("RENDER_GIT_COMMIT", "unknown"),
    }
