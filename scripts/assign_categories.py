#!/usr/bin/env python3
"""
assign_categories.py — Attribution rétroactive de la catégorie métier
aux items PENDING (ou APPROVED) sans catégorie.

Usage :
  python scripts/assign_categories.py            # simulation (dry-run)
  python scripts/assign_categories.py --apply    # écriture en base
  python scripts/assign_categories.py --all      # inclure APPROVED sans catégorie
  python scripts/assign_categories.py --apply --all
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

# ── Load .env ──────────────────────────────────────────────────
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

ANTHROPIC_MODEL = "claude-haiku-4-5"
KNOWN_CATEGORIES = {"clinique", "medicament", "dispositifs_medicaux", "facturation", "administratif", "sante_publique", "exercice"}

CATEGORY_PROMPT = """\
Assigne une catégorie métier parmi ces valeurs exactes :
  clinique              — recommandations HAS, protocoles, guidelines diagnostiques ou thérapeutiques
  medicament            — alertes pharmacovigilance sur une molécule nommée, retrait/suspension AMM, \
nouvelle indication, modification posologie/CI, remboursement médicament — STRICTEMENT pharmacologie
  dispositifs_medicaux  — alertes matériovigilance, équipements médicaux, imagerie (IRM, scanner, \
radiologie), implants, prothèses, instruments chirurgicaux, DM-DIV, réactifs laboratoire
  facturation           — CCAM, NGAP, tarifs, cotations, honoraires, remboursement actes
  administratif         — obligations déclaratives, formations DPC, certifications, accréditations
  sante_publique        — dépistage, vaccination, épidémies, prévention, plans nationaux
  exercice              — convention médicale, installation, déserts médicaux, gardes, télémédecine, \
statut libéral, logiciels métier (LAP, DMP, DxCare…)

Règle clé : si le texte porte sur un équipement/matériel médical plutôt que sur une molécule → dispositifs_medicaux.

Titre : {title}
Résumé : {summary}

Réponds UNIQUEMENT avec le mot-clé (ex: clinique)."""


# Variantes acceptées pour chaque catégorie
CATEGORY_ALIASES: dict[str, list[str]] = {
    "sante_publique":      ["sante_publique", "santé_publique", "sante publique", "santé publique",
                            "public health", "sante-publique", "santepublique"],
    "medicament":          ["medicament", "médicament"],
    "dispositifs_medicaux": ["dispositifs_medicaux", "dispositifs médicaux", "dispositif médical",
                             "dispositif_medical", "dm-div", "materiovigilance", "matériovigilance"],
    "clinique":            ["clinique"],
    "facturation":         ["facturation"],
    "administratif":       ["administratif"],
    "exercice":            ["exercice", "exercice libéral", "exercice liberal"],
}


def _parse_category(raw: str) -> str | None:
    """Normalise la réponse brute du LLM → catégorie canonique ou None."""
    s = raw.strip().lower()
    # Supprimer la ponctuation de fin
    s = s.rstrip(".,;:!?\"'")
    for canon, aliases in CATEGORY_ALIASES.items():
        for alias in aliases:
            if alias in s:
                return canon
    return None


async def assign_one(
    sem: asyncio.Semaphore,
    client: anthropic.AsyncAnthropic,
    item_id: str,
    title: str,
    summary: str,
) -> tuple[str, str | None]:
    """Retourne (item_id, categorie|None). Retry x3 sur rate limit."""
    prompt = CATEGORY_PROMPT.format(
        title=(title or "").strip()[:300],
        summary=(summary or "").strip()[:400],
    )
    async with sem:
        for attempt in range(4):          # 0, 1, 2, 3
            try:
                await asyncio.sleep(attempt * 2)   # backoff : 0s, 2s, 4s, 6s
                resp = await client.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=10,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = resp.content[0].text.strip()
                cat = _parse_category(raw)
                return item_id, cat
            except Exception as e:
                err_str = str(e)
                if "429" in err_str and attempt < 3:
                    wait = 15 * (attempt + 1)   # 15s, 30s, 45s
                    await asyncio.sleep(wait)
                    continue
                print(f"  ⚠️  item {item_id} — erreur LLM : {e}", file=sys.stderr)
                return item_id, None
        return item_id, None


async def run(apply: bool, include_all: bool) -> None:
    # ── Récupérer les items à traiter ──────────────────────────
    status_filter = "" if include_all else "AND i.review_status = 'PENDING'"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT i.id, c.title_raw, i.tri_json->>'resume' AS resume
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.categorie IS NULL
                  {status_filter}
                ORDER BY i.score_density DESC;
            """)
            rows = cur.fetchall()

    if not rows:
        print("✅ Aucun item sans catégorie — rien à faire.")
        return

    n = len(rows)
    # Estimation coût : ~200 tokens input + 5 tokens output par item
    # claude-haiku : $0.25/MTok input, $1.25/MTok output
    est_input_cost  = n * 200 / 1_000_000 * 0.25
    est_output_cost = n * 5   / 1_000_000 * 1.25
    est_total       = est_input_cost + est_output_cost

    print(f"{'='*55}")
    print(f"  Items à traiter : {n}")
    print(f"  Tokens estimés  : ~{n*200:,} input / ~{n*5:,} output")
    print(f"  Coût estimé     : ~${est_total:.4f} USD")
    print(f"  Mode            : {'APPLY (écriture DB)' if apply else 'DRY-RUN (simulation)'}")
    print(f"{'='*55}")

    if not apply:
        print("\n⚠️  Dry-run — relance avec --apply pour écrire en base.\n")
        # Afficher un aperçu des 5 premiers
        client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        sem = asyncio.Semaphore(5)
        sample = rows[:5]
        tasks = [assign_one(sem, client, str(r[0]), r[1] or "", r[2] or "") for r in sample]
        results = await asyncio.gather(*tasks)
        print("  Aperçu sur 5 articles :")
        for iid, cat in results:
            title = next(r[1] for r in sample if str(r[0]) == iid)
            print(f"    [{cat or '???':15s}] {(title or '')[:70]}")
        return

    # ── Run complet ────────────────────────────────────────────
    client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    sem = asyncio.Semaphore(5)
    tasks = [assign_one(sem, client, str(r[0]), r[1] or "", r[2] or "") for r in rows]

    results: list[tuple[str, str | None]] = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        iid, cat = await coro
        results.append((iid, cat))
        done += 1
        if done % 20 == 0 or done == n:
            print(f"  {done}/{n} traités…", end="\r")

    print(f"\n  {n}/{n} traités ✓")

    # ── Écriture en base ───────────────────────────────────────
    ok_results = [(cat, iid) for iid, cat in results if cat]
    failed    = [(iid, cat) for iid, cat in results if not cat]

    if ok_results:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    "UPDATE items SET categorie = %s WHERE id = %s::uuid;",
                    ok_results,
                )
            conn.commit()

    # ── Rapport ────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  Mis à jour : {len(ok_results)}")
    print(f"  Échecs     : {len(failed)}")
    print()

    from collections import Counter
    cats = Counter(cat for _, cat in results if cat)
    print("  Répartition par catégorie :")
    for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        bar = "█" * int(cnt / max(cats.values()) * 20)
        print(f"    {cat:15s} {cnt:4d}  {bar}")

    if failed:
        print(f"\n  ⚠️  {len(failed)} items sans catégorie assignée (LLM incertain)")
    print(f"{'='*55}")


def main():
    parser = argparse.ArgumentParser(description="Attribution rétroactive des catégories métier")
    parser.add_argument("--apply", action="store_true", help="Écrire en base (défaut: dry-run)")
    parser.add_argument("--all",   action="store_true", help="Inclure aussi les APPROVED sans catégorie")
    args = parser.parse_args()
    asyncio.run(run(apply=args.apply, include_all=args.all))


if __name__ == "__main__":
    main()
