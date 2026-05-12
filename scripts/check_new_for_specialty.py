#!/usr/bin/env python3
"""
Compte les candidates NEW pour le pipeline de triage automatique Hetzner.

Deux modes :
  python3 check_new_for_specialty.py global          → sources "tous" (triage global)
  python3 check_new_for_specialty.py <specialty_slug> → sources spécifiques à la spé

Option :
  --min-age-hours N  → ne compte que les candidats NEW depuis plus de N heures.
                       Utilisé par compute_backlog pour distinguer un vrai retard
                       d'une collecte fraîche qui attend simplement son slot prévu.

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


def _count_from_sources(sources: list[str], min_age_hours: int = 0) -> int:
    if not sources:
        return 0
    conn = psycopg2.connect(_load_db_url())
    try:
        cur = conn.cursor()
        placeholders = ",".join(["%s"] * len(sources))
        age_clause = ""
        params = sources
        if min_age_hours > 0:
            age_clause = f" AND created_at < NOW() - INTERVAL '{min_age_hours} hours'"
        cur.execute(
            f"SELECT COUNT(*) FROM candidates WHERE source IN ({placeholders}) AND status = 'NEW'{age_clause}",
            params,
        )
        return cur.fetchone()[0]
    finally:
        conn.close()


def count_new(arg: str, min_age_hours: int = 0) -> int:
    """
    arg='global'      → compte les NEW des sources "tous" (pour le triage global)
    arg=<slug>        → compte les NEW des sources spécifiques à la spécialité
                        (sources "tous" exclues — déjà traitées par le triage global)
    min_age_hours     → si > 0, ne compte que les candidats plus anciens que N heures
    """
    if arg == "global":
        return _count_from_sources(get_global_sources(), min_age_hours)
    return _count_from_sources(get_specialty_sources(arg), min_age_hours)


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(0)
        sys.exit(1)

    slug = args[0]
    min_age_hours = 0
    if "--min-age-hours" in args:
        idx = args.index("--min-age-hours")
        try:
            min_age_hours = int(args[idx + 1])
        except (IndexError, ValueError):
            pass

    try:
        print(count_new(slug, min_age_hours))
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print(0)
