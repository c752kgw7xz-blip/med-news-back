# app/migrations.py
from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from app.db import get_conn


def _repo_root() -> Path:
    # app/migrations.py -> app/ -> repo root
    return Path(__file__).resolve().parents[1]


def _sql_dir() -> Path:
    return _repo_root() / "sql"


def list_sql_migrations() -> List[Path]:
    sql_dir = _sql_dir()
    if not sql_dir.exists():
        return []
    # Tri lexical: 010_..., 020_..., etc.
    return sorted([p for p in sql_dir.glob("*.sql") if p.is_file()])


def ensure_migrations_table() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  filename TEXT PRIMARY KEY,
                  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )


def applied_migrations() -> set[str]:
    ensure_migrations_table()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT filename FROM schema_migrations;")
            rows = cur.fetchall()
    return {r[0] for r in rows}


def apply_migration_file(path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute(
                "INSERT INTO schema_migrations (filename) VALUES (%s) ON CONFLICT DO NOTHING;",
                (path.name,),
            )


def run_migrations() -> Tuple[int, List[str]]:
    """
    Returns: (applied_count, applied_filenames)
    """
    files = list_sql_migrations()
    if not files:
        return 0, []

    already = applied_migrations()
    applied_now: List[str] = []

    for f in files:
        if f.name in already:
            continue
        apply_migration_file(f)
        applied_now.append(f.name)

    return len(applied_now), applied_now

