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
            # min_size=0 : aucune connexion idle maintenue.
            # Neon free tier suspend la DB après ~5 min d'inactivité ;
            # garder des connexions idle les rend stales et fait crasher
            # la prochaine requête. Avec min_size=0, chaque connexion
            # est ouverte à la demande et Neon se réveille normalement.
            min_size=0,
            max_size=10,
            # open=False : n'essaie pas d'ouvrir des connexions au démarrage
            # (évite l'erreur si la DB n'est pas encore réveillée)
            open=False,
            # max_idle : ferme une connexion inutilisée après 4 min,
            # avant que Neon ne la suspende (5 min), évitant les stale connections
            max_idle=240,
            # reconnect_timeout : si l'ouverture échoue, réessaie pendant 30s
            reconnect_timeout=30,
            kwargs={
                "autocommit": False,
                # connect_timeout : laisse 10s à Neon pour sortir du sleep
                "connect_timeout": 10,
            },
        )
        _pool.open()
    return _pool


@contextmanager
def get_conn():
    """
    Fournit une connexion depuis le pool.
    Commits automatiquement on success, rollback on error.
    """
    pool = get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
