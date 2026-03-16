#!/usr/bin/env python3
"""
scripts/reclassify_medicaments.py — Détection des dispositifs médicaux mal classés en «medicament»

Soumet chaque item categorie=medicament à un prompt de triage et reclasse
en dispositifs_medicaux ceux qui portent sur un équipement/matériel médical.

Usage :
  python scripts/reclassify_medicaments.py           # dry-run (aperçu sans écriture)
  python scripts/reclassify_medicaments.py --apply   # écriture en base
"""

import argparse
import asyncio
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

import anthropic
from app.db import get_conn

ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"
BATCH_SIZE  = 20
BATCH_PAUSE = 1.0

TRIAGE_PROMPT = """\
Un article médical réglementaire a été classé dans la catégorie «medicament».
Détermine si cette classification est correcte ou si l'article porte en réalité \
sur un dispositif médical.

  medicament         — porte sur une MOLÉCULE nommée : alerte pharmacovigilance, \
retrait/suspension AMM, nouvelle indication, modification posologie/CI, \
remboursement d'un médicament (spécialité pharmaceutique).

  dispositifs_medicaux — porte sur un ÉQUIPEMENT ou MATÉRIEL médical : \
imagerie (IRM, scanner, radiologie, échographie), implants, prothèses, \
instruments chirurgicaux, DM-DIV, réactifs de laboratoire, matériovigilance, \
dispositifs connectés, logiciels médicaux au sens DM.

Règle décisive : si le texte mentionne un équipement/appareil/implant \
plutôt qu'une molécule → dispositifs_medicaux.

Titre   : {title}
Résumé  : {summary}

Réponds UNIQUEMENT avec l'un des deux mots-clés exacts :
medicament
dispositifs_medicaux"""


def _parse(raw: str) -> str | None:
    s = raw.strip().lower().rstrip(".,;:!?\"'")
    if "dispositifs_medicaux" in s or "dispositifs médicaux" in s or "dispositif" in s:
        return "dispositifs_medicaux"
    if "medicament" in s or "médicament" in s:
        return "medicament"
    return None


async def triage_one(
    sem: asyncio.Semaphore,
    client: anthropic.AsyncAnthropic,
    item_id: str,
    title: str,
    summary: str,
) -> tuple[str, str | None, str | None]:
    """Retourne (item_id, categorie_nouvelle|None, erreur|None)."""
    prompt = TRIAGE_PROMPT.format(
        title=(title or "").strip()[:300],
        summary=(summary or "").strip()[:400],
    )
    async with sem:
        for attempt in range(3):
            try:
                await asyncio.sleep(attempt * 2)
                resp = await client.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=10,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = resp.content[0].text.strip()
                cat = _parse(raw)
                return item_id, cat, None
            except Exception as e:
                err = str(e)
                if "429" in err and attempt < 2:
                    await asyncio.sleep(15 * (attempt + 1))
                    continue
                return item_id, None, err[:200]
        return item_id, None, "max retries"


async def run(apply: bool) -> None:
    # ── 1. Récupérer tous les items categorie=medicament ─────────
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, c.title_raw, i.tri_json->>'resume' AS resume,
                       i.review_status
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.categorie = 'medicament'
                ORDER BY i.score_density DESC NULLS LAST;
            """)
            rows = cur.fetchall()

    if not rows:
        print("✅ Aucun item categorie=medicament — rien à faire.")
        return

    n = len(rows)
    # claude-haiku : ~$0.25/MTok input + $1.25/MTok output — prompt très court ~200 tok
    est = n * 200 / 1e6 * 0.25 + n * 5 / 1e6 * 1.25

    print(f"{'='*60}")
    print(f"  Items categorie=medicament   : {n}")
    print(f"  Coût estimé                  : ~${est:.4f} USD")
    print(f"  Mode : {'APPLY (écriture DB)' if apply else 'DRY-RUN (simulation)'}")
    print(f"{'='*60}\n")

    items = [
        {"item_id": str(r[0]), "title": r[1], "summary": r[2] or "", "review_status": r[3]}
        for r in rows
    ]

    client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    sem    = asyncio.Semaphore(10)
    results: list[tuple[str, str | None, str | None]] = []

    # ── 2. Batches ───────────────────────────────────────────────
    n_batches = (n + BATCH_SIZE - 1) // BATCH_SIZE
    for i in range(n_batches):
        batch = items[i * BATCH_SIZE: (i + 1) * BATCH_SIZE]
        print(f"  Batch {i+1}/{n_batches} ({len(batch)} items)…", end=" ", flush=True)
        batch_res = await asyncio.gather(*[
            triage_one(sem, client, it["item_id"], it["title"], it["summary"])
            for it in batch
        ])
        results.extend(batch_res)
        ok = sum(1 for _, cat, err in batch_res if err is None)
        print(f"OK: {ok}/{len(batch)}")
        if i < n_batches - 1:
            await asyncio.sleep(BATCH_PAUSE)

    # ── 3. Analyse des résultats ─────────────────────────────────
    item_map = {it["item_id"]: it for it in items}
    to_dm   = [(iid, cat, err) for iid, cat, err in results if cat == "dispositifs_medicaux"]
    stays   = [(iid, cat, err) for iid, cat, err in results if cat == "medicament"]
    errors  = [(iid, cat, err) for iid, cat, err in results if err is not None]

    print(f"\n{'─'*60}")
    print(f"  Résultats :")
    print(f"    Maintenus medicament        : {len(stays)}")
    print(f"    → dispositifs_medicaux      : {len(to_dm)}")
    print(f"    Erreurs LLM                 : {len(errors)}")
    print(f"{'─'*60}")

    if to_dm:
        print("\n  Reclassifiés → dispositifs_medicaux :")
        for iid, _, _ in to_dm:
            it = item_map[iid]
            print(f"    [{it['review_status']}] {it['title'][:72]}")

    if errors:
        print(f"\n  ⚠️  Erreurs ({len(errors)}) :")
        for iid, _, err in errors:
            it = item_map[iid]
            print(f"    {it['title'][:55]} — {err}")

    # ── 4. Écriture en base ──────────────────────────────────────
    if not apply:
        print(f"\n⚠️  Dry-run — {len(to_dm)} items seraient modifiés.")
        print("    Relance avec --apply pour écrire en base.\n")
        return

    if not to_dm:
        print("\n✅ Aucun changement à écrire.\n")
        return

    print(f"\n  Écriture de {len(to_dm)} items en base…")
    updated = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for iid, _, _ in to_dm:
                cur.execute(
                    "UPDATE items SET categorie = 'dispositifs_medicaux' WHERE id = %s::uuid;",
                    (iid,),
                )
                updated += cur.rowcount

    print(f"\n{'='*60}")
    print(f"  RÉSUMÉ FINAL")
    print(f"    Maintenus medicament        : {len(stays)}")
    print(f"    → dispositifs_medicaux      : {updated}")
    print(f"    Erreurs (non modifiés)      : {len(errors)}")
    print(f"{'='*60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reclasse les items medicament qui sont réellement des dispositifs médicaux"
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Écrire les changements en base (défaut : dry-run)"
    )
    args = parser.parse_args()
    asyncio.run(run(args.apply))


if __name__ == "__main__":
    main()
