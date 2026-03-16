#!/usr/bin/env python3
"""
Ré-analyse les items PENDING TRANSVERSAL_LIBERAL de sources ansm_securite,
has_rbp et bo_social avec le prompt mis à jour.

Usage :
  python scripts/reanalyze_transversal.py           # dry-run (affiche sans modifier)
  python scripts/reanalyze_transversal.py --apply   # applique les corrections en base
"""

import asyncio
import json
import os
import sys

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("✗ DATABASE_URL manquant dans .env")
    sys.exit(1)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import psycopg
from psycopg.types.json import Json

from app.llm_analysis import call_claude_async, ANTHROPIC_MODEL

def fetch_suspects() -> list[dict]:
    conn = psycopg.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.id, c.title_raw, c.content_raw, c.official_date::text,
                       c.source, i.audience, i.specialty_slug, i.score_density
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'PENDING'
                  AND i.audience = 'TRANSVERSAL_LIBERAL'
                ORDER BY i.score_density DESC
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "item_id": str(r[0]),
            "title": r[1],
            "content": r[2],
            "date": r[3],
            "source": r[4],
            "audience_before": r[5],
            "specialty_before": r[6],
            "score_before": r[7],
        }
        for r in rows
    ]


async def reanalyze_all(items: list[dict], apply: bool) -> None:
    semaphore = asyncio.Semaphore(5)

    async def process(item: dict) -> dict:
        async with semaphore:
            result = await call_claude_async(
                item["title"],
                item["content"],
                item["date"],
                source=item["source"],
            )
            return {**item, "result": result}

    tasks = [process(item) for item in items]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    changed = 0
    errors = 0

    conn = psycopg.connect(DATABASE_URL) if apply else None
    try:
        for r in results:
            if isinstance(r, Exception):
                errors += 1
                print(f"  ✗ Erreur LLM : {r}")
                continue

            item = r
            res = item["result"]
            audience_after = res.get("audience", "TRANSVERSAL_LIBERAL")
            specialites_after = res.get("specialites", [])
            score_after = res.get("score_density", item["score_before"])
            tri_after = res.get("tri_json", {})
            lecture_after = res.get("lecture_json", {})

            # Déterminer les slugs à écrire
            if audience_after in ("TRANSVERSAL_LIBERAL", "PHARMACIENS") or not specialites_after:
                slugs_after = [None]
            else:
                slugs_after = specialites_after

            # Affichage avant/après
            slug_before_str = item["specialty_before"] or "TRANSVERSAL"
            slug_after_str = ", ".join(str(s) for s in slugs_after) if slugs_after != [None] else "TRANSVERSAL"

            print(f"\n{'─'*70}")
            print(f"  Titre  : {item['title'][:80]}")
            print(f"  Source : {item['source']}")
            print(f"  Avant  : {item['audience_before']} / {slug_before_str} [{item['score_before']}/10]")
            print(f"  Après  : {audience_after} / {slug_after_str} [{score_after}/10]")

            if audience_after != item["audience_before"] or slugs_after != [item["specialty_before"]]:
                print("  → MODIFIÉ")
                changed += 1
            else:
                print("  → inchangé")
                continue  # Pas d'écriture si identique

            if not apply:
                continue

            # Mise à jour : on modifie l'item existant avec le premier slug
            # Si plusieurs slugs nouveaux → l'item TRANSVERSAL devient le premier, pas d'insertion de doublons
            first_slug = slugs_after[0]
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE items
                    SET audience       = %s,
                        specialty_slug = %s,
                        score_density  = %s,
                        tri_json       = %s,
                        lecture_json   = %s,
                        llm_model      = %s
                    WHERE id = %s
                    """,
                    (
                        audience_after,
                        first_slug,
                        score_after,
                        Json(tri_after),
                        Json(lecture_after),
                        ANTHROPIC_MODEL,
                        item["item_id"],
                    ),
                )
            print(f"  ✓ item {item['item_id']} mis à jour en base")

        if apply and conn:
            conn.commit()

    finally:
        if conn:
            conn.close()

    print(f"\n{'='*70}")
    print(f"Total : {len(results)} items analysés")
    print(f"  Modifiés : {changed}")
    print(f"  Erreurs  : {errors}")
    if not apply:
        print("\n⚠ Mode dry-run — aucune modification en base.")
        print("Relancer avec --apply pour appliquer.")


def main():
    apply = "--apply" in sys.argv

    print(f"{'='*70}")
    print(f"Ré-analyse TRANSVERSAL suspects — toutes sources")
    print(f"Mode : {'APPLY' if apply else 'DRY-RUN'}")
    print(f"{'='*70}")

    items = fetch_suspects()
    if not items:
        print("✗ Aucun item TRANSVERSAL_LIBERAL PENDING.")
        sys.exit(0)

    print(f"→ {len(items)} items à ré-analyser\n")

    asyncio.run(reanalyze_all(items, apply=apply))


if __name__ == "__main__":
    main()
