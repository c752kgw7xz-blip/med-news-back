import os
import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Med Newsletter API", version="0.1.0")

# CORS: autorise les sites Netlify
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En prod, remplacez par votre URL Netlify exacte
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Med Newsletter API", "version": app.version}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/version")
def version():
    return {"version": app.version}

@app.get("/db-check")
def db_check():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise HTTPException(status_code=500, detail="DATABASE_URL not set")

    try:
        with psycopg.connect(db_url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()
        return {"db": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
