# app/db.py
import os
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

_pool: ConnectionPool | None = None


def get_database_url() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is missing in environment.")
    return dsn


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            get_database_url(),
            min_size=2,
            max_size=10,
            kwargs={"autocommit": False},
        )
    return _pool


@contextmanager
def get_conn():
    """
    Fournit une connexion depuis le pool.
    Commits automatiquement on success, rollback on error.

    Usage identique à l'ancienne version :
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(...)
    """
    pool = get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
