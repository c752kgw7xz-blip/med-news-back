# app/db.py
import os
from contextlib import contextmanager

import psycopg


def get_database_url() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is missing in environment.")
    return dsn


@contextmanager
def get_conn():
    """
    Usage:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(...)
    Commits automatically on success, rollbacks on error.
    """
    conn = psycopg.connect(get_database_url())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
