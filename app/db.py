# app/db.py
import logging
import os
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

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
            # min_size=0 : aucune connexion idle maintenue → compatible Neon auto-suspend
            # (Neon suspend la DB après ~5 min d'inactivité ; une connexion idle
            #  devient stale et fait échouer la requête suivante)
            min_size=0,
            max_size=10,
            # Ouvre une connexion à la demande, sans attendre au démarrage
            open=False,
            # Reconnexion automatique si une connexion du pool est morte
            reconnect_timeout=30,
            kwargs={
                "autocommit": False,
                # Timeout de connexion : laisse le temps à Neon de sortir du sleep (~2s)
                "connect_timeout": 10,
                "options": "-c statement_timeout=30000",
            },
        )
        _pool.open()
    return _pool


@contextmanager
def get_conn():
    """
    Fournit une connexion depuis le pool.
    Commits automatiquement on success, rollback on error.
    Retry automatique une fois si la connexion est stale (Neon auto-suspend).
    """
    pool = get_pool()
    for attempt in range(2):
        try:
            with pool.connection() as conn:
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
            return  # succès
        except psycopg.OperationalError as exc:
            if attempt == 0:
                logger.warning("DB connexion stale, retry… (%s)", exc)
                continue
            raise
