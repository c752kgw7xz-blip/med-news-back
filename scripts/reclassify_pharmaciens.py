#!/usr/bin/env python3
"""
scripts/reclassify_pharmaciens.py — Reclassification des items audience=PHARMACIENS

Soumet chaque article PHARMACIENS au prompt de classification actuel et met à jour
audience, specialty_slug et score_density en base si le résultat a changé.

Usage :
  python scripts/reclassify_pharmaciens.py           # dry-run (aperçu sans écriture)
  python scripts/reclassify_pharmaciens.py --apply   # écriture en base
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
env_path = ROOT / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            v = v.strip().strip('"').strip("'")
            if v:
                os.environ[k.strip()] = v

sys.path.insert(0, str(ROOT))

from app.db import get_conn
from app.llm_analysis import call_claude_async

BATCH_SIZE  = 10
BATCH_PAUSE = 1.0   # secondes entre batches


async def reclassify_one(
    sem: asyncio.Semaphore,
    item_id: str,
    title: str,
    content: str | None,
    date_pub: str,
    source: str | None,
) -> dict:
    async with sem:
        try:
            result = await call_claude_async(title, content, date_pub, source=source)
            return {
                "item_id":       item_id,
                "audience":      result.get("audience", "TRANSVERSAL_LIBERAL"),
                "specialites":   result.get("specialites", []),
                "score_density": result.get("score_density", 5),
                "llm_raw":       json.dumps(result, ensure_ascii=False),
                "error":         None,
            }
        except Exception as e:
            return {
                "item_id": item_id, "audience": None, "specialites": [],
                "score_density": None, "llm_raw": None, "error": str(e)[:300],
            }


async def run(apply: bool, only_specialite: bool = False) -> None:
    # ── 1. Récupérer tous les items PHARMACIENS ──────────────────
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, c.title_raw, c.content_raw,
                       c.official_date::text, c.source, i.review_status
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.audience = 'PHARMACIENS'
                ORDER BY i.score_density DESC NULLS LAST;
            """)
            rows = cur.fetchall()

    if not rows:
        print("✅ Aucun item avec audience = PHARMACIENS — rien à faire.")
        return

    n = len(rows)
    # claude-haiku-4-5 : ~$0.80/MTok input, ~$4/MTok output
    # Prompt complet ≈ 1 200 tokens input + 400 output par item
    est = n * 1200 / 1e6 * 0.80 + n * 400 / 1e6 * 4.00

    print(f"{'='*58}")
    print(f"  Articles PHARMACIENS en base : {n}")
    print(f"  Coût estimé                  : ~${est:.4f} USD")
    print(f"  Mode  : {'APPLY (écriture DB)' if apply else 'DRY-RUN (simulation)'}")
    print(f"{'='*58}\n")

    items = [
        {"item_id": str(r[0]), "title": r[1], "content": r[2],
         "date": r[3], "source": r[4], "review_status": r[5]}
        for r in rows
    ]

    sem     = asyncio.Semaphore(10)
    results: list[dict] = []

    # ── 2. Batches de BATCH_SIZE avec pause ──────────────────────
    n_batches = (n + BATCH_SIZE - 1) // BATCH_SIZE
    for i in range(n_batches):
        batch = items[i * BATCH_SIZE : (i + 1) * BATCH_SIZE]
        print(f"  Batch {i+1}/{n_batches} ({len(batch)} items)…", end=" ", flush=True)
        batch_res = await asyncio.gather(*[
            reclassify_one(sem, it["item_id"], it["title"],
                           it["content"], it["date"], it["source"])
            for it in batch
        ])
        results.extend(batch_res)
        ok = sum(1 for r in batch_res if r["error"] is None)
        print(f"OK: {ok}/{len(batch)}")
        if i < n_batches - 1:
            await asyncio.sleep(BATCH_PAUSE)

    # ── 3. Tri des résultats ─────────────────────────────────────
    ok_res   = [r for r in results if r["error"] is None]
    err_res  = [r for r in results if r["error"] is not None]

    stayed   = [r for r in ok_res if r["audience"] == "PHARMACIENS"]
    to_spec  = [r for r in ok_res if r["audience"] == "SPECIALITE"]
    to_trans = [r for r in ok_res if r["audience"] == "TRANSVERSAL_LIBERAL"]

    item_map = {it["item_id"]: it for it in items}

    print(f"\n{'─'*58}")
    print(f"  Résultats LLM :")
    print(f"    Maintenus PHARMACIENS    : {len(stayed)}")
    print(f"    → SPECIALITE             : {len(to_spec)}")
    print(f"    → TRANSVERSAL_LIBERAL    : {len(to_trans)}")
    print(f"    Erreurs LLM              : {len(err_res)}")
    print(f"{'─'*58}")

    if to_spec:
        print("\n  Reclassifiés → SPECIALITE :")
        for r in to_spec:
            it = item_map[r["item_id"]]
            slugs = ", ".join(r["specialites"]) or "?"
            print(f"    [{it['review_status']}] {it['title'][:68]}")
            print(f"           → {slugs}")

    if to_trans:
        print("\n  Reclassifiés → TRANSVERSAL_LIBERAL :")
        for r in to_trans:
            it = item_map[r["item_id"]]
            print(f"    [{it['review_status']}] {it['title'][:68]}")

    if stayed:
        print(f"\n  Maintenus PHARMACIENS ({len(stayed)}) :")
        for r in stayed:
            it = item_map[r["item_id"]]
            print(f"    [{it['review_status']}] {it['title'][:68]}")

    if err_res:
        print(f"\n  ⚠️  Erreurs ({len(err_res)}) :")
        for r in err_res:
            it = item_map[r["item_id"]]
            print(f"    {it['title'][:60]} — {r['error']}")

    # ── 4. Écriture en base ──────────────────────────────────────
    if only_specialite:
        changed = [r for r in ok_res if r["audience"] == "SPECIALITE"]
    else:
        changed = [r for r in ok_res if r["audience"] != "PHARMACIENS"]

    if not apply:
        filter_note = " (--only-specialite : TRANSVERSAL_LIBERAL ignorés)" if only_specialite else ""
        print(f"\n⚠️  Dry-run — {len(changed)} items seraient modifiés{filter_note}.")
        print("    Relance avec --apply pour écrire en base.\n")
        return

    if not changed:
        print("\n✅ Aucun changement à écrire.\n")
        return

    print(f"\n  Écriture de {len(changed)} items en base…")
    updated = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for r in changed:
                new_audience = r["audience"]
                # SPECIALITE → premier slug (specialty_slug = TEXT, 1 item par candidate)
                new_slug = (
                    r["specialites"][0]
                    if new_audience == "SPECIALITE" and r["specialites"]
                    else None
                )
                cur.execute(
                    """
                    UPDATE items
                    SET audience       = %s,
                        specialty_slug = %s,
                        score_density  = %s,
                        llm_raw        = %s
                    WHERE id = %s::uuid;
                    """,
                    (new_audience, new_slug, r["score_density"],
                     r["llm_raw"], r["item_id"]),
                )
                updated += cur.rowcount

    print(f"\n{'='*58}")
    print(f"  RÉSUMÉ FINAL")
    print(f"    Maintenus PHARMACIENS    : {len(stayed)}")
    print(f"    → SPECIALITE             : {len(to_spec)}")
    print(f"    → TRANSVERSAL_LIBERAL    : {len(to_trans)}")
    print(f"    Écrits en base           : {updated}")
    print(f"    Erreurs (non mis à jour) : {len(err_res)}")
    print(f"{'='*58}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reclassifie les items audience=PHARMACIENS via le prompt LLM actuel"
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Écrire les changements en base (défaut : dry-run)"
    )
    parser.add_argument(
        "--only-specialite", action="store_true",
        help="N'écrire que les reclassifications vers SPECIALITE (ignorer TRANSVERSAL_LIBERAL)"
    )
    args = parser.parse_args()
    asyncio.run(run(args.apply, args.only_specialite))


if __name__ == "__main__":
    main()
