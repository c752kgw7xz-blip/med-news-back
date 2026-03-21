#!/usr/bin/env python3
"""
Pré-filtre local des candidats NEW — 0 appel LLM, 0 dépendance serveur.

Lance directement depuis ton Mac contre Neon DB.

Usage :
    python scripts/pre_filter_run.py              # tous les NEW
    python scripts/pre_filter_run.py --dry-run    # simulation sans écriture
    python scripts/pre_filter_run.py --batch 200  # taille de lot
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# ── Setup path ───────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env", override=True)

import psycopg
from app.llm_analysis import pre_filter_candidate

# ── Args ─────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Pré-filtre local candidates NEW")
parser.add_argument("--batch", type=int, default=500, help="Taille de lot (défaut 500)")
parser.add_argument("--dry-run", action="store_true", help="Simulation sans écriture DB")
args = parser.parse_args()

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("❌  DATABASE_URL manquant dans .env")
    sys.exit(1)

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(f"{'[DRY-RUN] ' if args.dry_run else ''}Connexion à Neon DB…")
    t0 = time.time()

    with psycopg.connect(DATABASE_URL) as conn:
        # Compte initial
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status = 'NEW';")
            total_new = cur.fetchone()[0]

        print(f"📊  {total_new} candidats NEW à traiter (batch={args.batch})\n")

        eliminated = kept = batch_n = 0
        last_id = "00000000-0000-0000-0000-000000000000"  # UUID minimal

        while True:
            # Pagination par curseur UUID — stable même si des records changent de status
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, title_raw, source
                    FROM candidates
                    WHERE status = 'NEW'
                      AND id > %s::uuid
                    ORDER BY id
                    LIMIT %s;
                    """,
                    (last_id, args.batch),
                )
                rows = cur.fetchall()

            if not rows:
                break

            batch_n += 1
            last_id = str(rows[-1][0])  # avance le curseur
            to_eliminate: list[str] = []

            for (cid, title_raw, source) in rows:
                keep, reason = pre_filter_candidate(title_raw or "", source=source or "")
                if not keep:
                    to_eliminate.append(str(cid))
                else:
                    kept += 1

            if to_eliminate and not args.dry_run:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE candidates SET status = 'LLM_DONE' WHERE id = ANY(%s::uuid[]);",
                        (to_eliminate,),
                    )
                conn.commit()

            eliminated += len(to_eliminate)
            processed = eliminated + kept
            pct = round(processed / total_new * 100) if total_new else 0

            print(
                f"  Lot {batch_n:>3} | traités {processed:>5}/{total_new}"
                f"  ({pct:>3}%) | éliminés {eliminated:>5} | conservés {kept:>5}"
                + (" [DRY-RUN]" if args.dry_run else "")
            )

            # Si le batch n'est pas plein, on a tout traité
            if len(rows) < args.batch:
                break

    elapsed = round(time.time() - t0, 1)
    print(f"\n{'[DRY-RUN] ' if args.dry_run else ''}✅  Terminé en {elapsed}s")
    print(f"   Éliminés  : {eliminated}  (→ LLM_DONE, 0 appel LLM)")
    print(f"   Conservés : {kept}  (→ restent NEW, prêts pour LLM)")
    if args.dry_run:
        print("   ⚠️  Dry-run : aucune écriture en base.")
    else:
        pct_elim = round(eliminated / (eliminated + kept) * 100) if (eliminated + kept) else 0
        print(f"   Taux d'élimination : {pct_elim}%")


if __name__ == "__main__":
    main()
