import os
import psycopg
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL")
DB_INIT_SECRET = os.environ.get("DB_INIT_SECRET")

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

def get_conn():
  if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")
  return psycopg.connect(DATABASE_URL)

@app.get("/health/db")
def health_db():
  try:
    with get_conn() as conn:
      with conn.cursor() as cur:
        cur.execute("select 1;")
        return {"ok": True}
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))

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
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))
