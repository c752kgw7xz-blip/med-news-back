#!/usr/bin/env python3
"""
Compte les candidates NEW pour le pipeline de triage automatique Hetzner.

Deux modes :
  python3 check_new_for_specialty.py global          → sources "tous" (triage global)
  python3 check_new_for_specialty.py <specialty_slug> → sources spécifiques à la spé

Architecture deux passes :
  1. "triage global"  : traite sources hint="tous" une seule fois → LLM_DONE
  2. "lance X"        : ne voit que les sources spécifiques à X (les "tous" sont déjà LLM_DONE)
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import psycopg2
from app.llm_analysis import SOURCE_SPECIALTY_HINTS


def _load_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("DATABASE_URL="):
                    return line.split("=", 1)[1].strip("\"'")
    raise RuntimeError("DATABASE_URL introuvable")


def get_specialty_sources(slug: str) -> list[str]:
    """Sources spécifiques à cette spécialité (exclut hint='tous')."""
    return [src for src, hint in SOURCE_SPECIALTY_HINTS.items() if hint == slug]


def get_global_sources() -> list[str]:
    """Sources communes à toutes les spécialités (hint='tous')."""
    return [src for src, hint in SOURCE_SPECIALTY_HINTS.items() if hint == "tous"]


def _count_from_sources(sources: list[str]) -> int:
    if not sources:
        return 0
    conn = psycopg2.connect(_load_db_url())
    try:
        cur = conn.cursor()
        placeholders = ",".join(["%s"] * len(sources))
        cur.execute(
            f"SELECT COUNT(*) FROM candidates WHERE source IN ({placeholders}) AND status = 'NEW'",
            sources,
        )
        return cur.fetchone()[0]
    finally:
        conn.close()


def count_new(arg: str) -> int:
    """
    arg='global'      → compte les NEW des sources "tous" (pour le triage global)
    arg=<slug>        → compte les NEW des sources spécifiques à la spécialité
                        (sources "tous" exclues — déjà traitées par le triage global)
    """
    if arg == "global":
        return _count_from_sources(get_global_sources())
    return _count_from_sources(get_specialty_sources(arg))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(0)
        sys.exit(1)
    try:
        print(count_new(sys.argv[1]))
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print(0)
