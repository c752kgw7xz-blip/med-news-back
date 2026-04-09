"""
scripts/migrate_innovation_source_type.py
-----------------------------------------
Migration DB : met à jour source_type = 'innovation' pour les items existants
dont la source correspond à la section Innovation.

Sources concernées (23) :
  • ema_new_medicines        → EMA nouvelles AMM européennes
  • 12 revues JAMA + JAMA Network Open (Silverchair RSS)
  • 4 revues médicales haut-volume (NEJM, Lancet, BMJ, Nature Medicine)
  • 6 revues paramédicales (Clinical Chemistry, PTJ, BJOG, CPT, JDR, JAN)

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
    # EMA
    "ema_new_medicines",
    # JAMA Network (Silverchair)
    "jama",
    "jama_cardiology",
    "jama_dermatology",
    "jama_internal_med",
    "jama_neurology",
    "jama_oncology",
    "jama_ophthalmology",
    "jama_otolaryngology",
    "jama_pediatrics",
    "jama_psychiatry",
    "jama_surgery",
    "jama_network_open",
    # Revues généralistes haut-volume
    "nejm",
    "lancet",
    "bmj",
    "nature_medicine",
    # Paramédical
    "clinical_chemistry",
    "ptj_kine",
    "bjog",
    "cpt_pharmacol",
    "jdr_dental",
    "jan_nursing",
]


async def main(dry_run: bool) -> None:
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        total_to_update = 0
        for source in INNOVATION_SOURCES:
            rows = await conn.fetch(
                """
                SELECT i.id, c.title_raw, i.source_type
                FROM   items i
                JOIN   candidates c ON c.id = i.candidate_id
                WHERE  c.source = $1
                  AND  i.source_type != 'innovation'
                """,
                source,
            )
            count = len(rows)
            if count == 0:
                print(f"✅  source={source!r} — aucun item à migrer (déjà à jour ou absent).")
                continue

            total_to_update += count
            print(f"\n{'[DRY-RUN] ' if dry_run else ''}source={source!r} — {count} item(s) à passer en 'innovation' :")
            for r in rows[:5]:
                print(f"    id={r['id']}  source_type_actuel={r['source_type']!r}  titre={r['title_raw'][:70]!r}")
            if count > 5:
                print(f"    … et {count - 5} autres.")

            if not dry_run:
                result = await conn.execute(
                    """
                    UPDATE items
                    SET    source_type = 'innovation'
                    WHERE  source_type != 'innovation'
                      AND  candidate_id IN (
                        SELECT id FROM candidates WHERE source = $1
                      )
                    """,
                    source,
                )
                print(f"    → {result}")

        print(f"\n{'[DRY-RUN] ' if dry_run else ''}Total : {total_to_update} item(s) concerné(s).")
        if dry_run:
            print("⚠️   Mode dry-run : aucune modification effectuée. Relancez avec --apply.")
        else:
            print("✅  Migration terminée.")
    finally:
        await conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migre source_type → innovation pour les sources concernées.")
    parser.add_argument("--apply", action="store_true", help="Applique les modifications (sans ce flag = dry-run).")
    args = parser.parse_args()
    asyncio.run(main(dry_run=not args.apply))
