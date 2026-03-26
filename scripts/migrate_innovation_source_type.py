"""
scripts/migrate_innovation_source_type.py
-----------------------------------------
Migration DB : met à jour source_type = 'innovation' pour les items existants
dont la source correspond à la nouvelle section Innovation.

Sources concernées :
  • ema_new_medicines  → EMA nouvelles AMM européennes

Usage :
    python scripts/migrate_innovation_source_type.py           # dry-run (aperçu)
    python scripts/migrate_innovation_source_type.py --apply   # exécute la mise à jour
"""

import asyncio
import argparse
import os
import sys

import asyncpg

DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    print("❌  Env var DATABASE_URL manquante.", file=sys.stderr)
    sys.exit(1)

# Sources qui passent dans la section Innovation
INNOVATION_SOURCES: list[str] = [
    "ema_new_medicines",  # EMA — nouvelles AMM européennes (~200/an)
]


async def main(dry_run: bool) -> None:
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        for source in INNOVATION_SOURCES:
            rows = await conn.fetch(
                """
                SELECT id, title_raw, source_type
                FROM   news_items
                WHERE  source = $1
                  AND  source_type != 'innovation'
                """,
                source,
            )
            count = len(rows)
            if count == 0:
                print(f"✅  source={source!r} — aucun item à migrer (déjà à jour ou absent).")
                continue

            print(f"\n{'[DRY-RUN] ' if dry_run else ''}source={source!r} — {count} item(s) à passer en 'innovation' :")
            for r in rows[:10]:
                print(f"    id={r['id']}  source_type_actuel={r['source_type']!r}  titre={r['title_raw'][:70]!r}")
            if count > 10:
                print(f"    … et {count - 10} autres.")

            if not dry_run:
                updated = await conn.execute(
                    """
                    UPDATE news_items
                    SET    source_type = 'innovation'
                    WHERE  source = $1
                      AND  source_type != 'innovation'
                    """,
                    source,
                )
                print(f"    → {updated}")
        if dry_run:
            print("\n⚠️   Mode dry-run : aucune modification effectuée. Relancez avec --apply.")
        else:
            print("\n✅  Migration terminée.")
    finally:
        await conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migre source_type → innovation pour les sources concernées.")
    parser.add_argument("--apply", action="store_true", help="Applique les modifications (sans ce flag = dry-run).")
    args = parser.parse_args()
    asyncio.run(main(dry_run=not args.apply))
