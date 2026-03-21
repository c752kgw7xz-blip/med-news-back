#!/usr/bin/env python3
"""
Lancement contrôlé de l'analyse LLM sur les candidats NEW/LLM_FAILED.
Migration Claude Haiku (Anthropic async, 20 concurrent).

Usage :
    python scripts/run_llm_analysis.py --limit 20
    python scripts/run_llm_analysis.py --limit 3190 --yes   # sans confirmation
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Charger l'environnement ──────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env", override=True)

import psycopg
from psycopg.types.json import Json

from app.llm_analysis import (
    ANTHROPIC_MODEL,
    analyse_candidate_async,
    pre_filter_candidate,
    get_source_config,
    get_source_type,
)

# ---------------------------------------------------------------------------
MAX_CONCURRENT = 8  # réduit pour éviter les 429 en rafale sur Anthropic
# ---------------------------------------------------------------------------


def get_conn():
    return psycopg.connect(os.environ["DATABASE_URL"])


def fetch_batch(limit: int) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, title_raw, content_raw, official_date::text, source
                FROM candidates
                WHERE status IN ('NEW', 'LLM_FAILED')
                ORDER BY official_date DESC
                LIMIT %s;
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [
        {
            "id": str(r[0]),
            "title_raw": r[1],
            "content_raw": r[2],
            "official_date": r[3],
            "source": r[4] or "",
        }
        for r in rows
    ]


def count_remaining() -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status IN ('NEW', 'LLM_FAILED')")
            return cur.fetchone()[0]


INSERT_ITEM_SQL = """
INSERT INTO items (
    candidate_id, audience, specialty_slug,
    tri_json, lecture_json, score_density,
    categorie, type_praticien, source_type,
    llm_raw, llm_model, review_status
)
VALUES (
    %(candidate_id)s, %(audience)s, %(specialty_slug)s,
    %(tri_json)s, %(lecture_json)s, %(score_density)s,
    %(categorie)s, %(type_praticien)s, %(source_type)s,
    %(llm_raw)s, %(llm_model)s, 'PENDING'
)
ON CONFLICT (candidate_id, COALESCE(specialty_slug, '')) DO NOTHING
RETURNING id;
"""


def _db_mark_filtered(cid: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;", (cid,))


def _db_mark_failed(cid: str, error: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE candidates SET status = 'LLM_FAILED', llm_error = %s WHERE id = %s;",
                (error[:500], cid),
            )


def _db_insert_result(cid: str, result: dict, source: str | None = None) -> list[str]:
    score       = result.get("score_density", 0)
    audience    = result.get("audience", "SPECIALITE")
    if audience not in ("SPECIALITE", "PHARMACIENS"):
        audience = "SPECIALITE"
    specialites = result.get("specialites", [])
    llm_raw     = json.dumps(result, ensure_ascii=False)
    source_type = get_source_type(source)

    # Seuil par source (min_llm_score)
    min_score = get_source_config(source).get("min_llm_score", 5)
    if not result.get("pertinent", True) or score < min_score:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;", (cid,))
        return []

    # PHARMACIENS → 1 item slug='pharmacien' ; SPECIALITE → 1 item par spécialité
    if audience == "PHARMACIENS":
        slugs: list[str] = ["pharmacien"]
    else:
        slugs = specialites if specialites else ["medecine-generale"]

    item_ids: list[str] = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            for slug in slugs:
                params = {
                    "candidate_id": cid,
                    "audience": audience,
                    "specialty_slug": slug,
                    "tri_json": Json(result.get("tri_json", {})),
                    "lecture_json": Json(result.get("lecture_json", {})),
                    "score_density": score,
                    "categorie": result.get("categorie"),
                    "type_praticien": result.get("type_praticien"),
                    "source_type": source_type,
                    "llm_raw": llm_raw,
                    "llm_model": result.get("llm_model", ANTHROPIC_MODEL),
                }
                cur.execute(INSERT_ITEM_SQL, params)
                row = cur.fetchone()
                if row:
                    item_ids.append(str(row[0]))
            cur.execute("UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;", (cid,))
    return item_ids


# ---------------------------------------------------------------------------
# Cœur async
# ---------------------------------------------------------------------------

async def _process_async(
    candidate: dict,
    semaphore: asyncio.Semaphore,
    counter: list,
    total: int,
) -> dict:
    cid   = candidate["id"]
    title = candidate["title_raw"]
    report: dict = {"candidate_id": cid, "title": title[:80]}

    # Pré-filtre (CPU, pas de réseau)
    keep, drop_reason = pre_filter_candidate(title, source=candidate.get("source"))
    if not keep:
        _db_mark_filtered(cid)
        report["status"]      = "PRE_FILTERED"
        report["drop_reason"] = drop_reason
        counter[0] += 1
        _print_progress(counter[0], total, cid, "PRE_FILTERED", drop_reason or "")
        return report

    async with semaphore:
        try:
            result = await analyse_candidate_async(
                candidate_id=cid,
                title_raw=title,
                content_raw=candidate["content_raw"],
                official_date=candidate["official_date"],
                source=candidate.get("source"),
            )
        except Exception as e:
            _db_mark_failed(cid, str(e))
            report["status"] = "LLM_FAILED"
            report["error"]  = str(e)[:200]
            counter[0] += 1
            _print_progress(counter[0], total, cid, "LLM_FAILED", str(e)[:50])
            return report

    # DB (sync — rapide, pas de réseau distant)
    score    = result.get("score_density", 0)
    pertinent = result.get("pertinent", True)
    item_ids = _db_insert_result(cid, result, source=candidate.get("source"))

    min_score = get_source_config(candidate.get("source")).get("min_llm_score", 5)
    if not pertinent or score < min_score:
        report["status"] = "LLM_DONE_NOT_PERTINENT"
        report["score_density"] = score
    else:
        report["status"]    = "LLM_DONE"
        report["pertinent"] = True
        report["audience"]  = result.get("audience")
        report["specialites"] = result.get("specialites", [])
        report["score_density"] = score
        report["item_ids"]  = item_ids

    counter[0] += 1
    suffix = f"score={score} items={len(item_ids)}" if item_ids else f"score={score}"
    _print_progress(counter[0], total, cid, report["status"], suffix)
    return report


_print_lock = asyncio.Lock() if False else None  # créé dans main


async def _print_progress_async(lock, n, total, cid, status, detail):
    async with lock:
        bar = f"[{n:>4}/{total}]"
        print(f"  {bar} {status:<26} {cid[:8]}  {detail[:60]}", flush=True)


def _print_progress(n, total, cid, status, detail):
    bar = f"[{n:>4}/{total}]"
    print(f"  {bar} {status:<26} {cid[:8]}  {detail[:60]}", flush=True)


def print_report(reports: list[dict], elapsed: float, input_tokens: int = 0, output_tokens: int = 0) -> None:
    counts: dict[str, int] = defaultdict(int)
    scores: list[int] = []

    for r in reports:
        s = r.get("status", "?")
        counts[s] += 1
        if "score_density" in r:
            scores.append(r["score_density"])

    total      = len(reports)
    llm_calls  = counts["LLM_DONE"] + counts["LLM_DONE_NOT_PERTINENT"] + counts["LLM_FAILED"]
    items_created = sum(len(r.get("item_ids", [])) for r in reports)

    # Estimation coût Haiku : $0.80/M input, $4.00/M output
    cost_usd   = (input_tokens / 1_000_000) * 0.80 + (output_tokens / 1_000_000) * 4.0

    print()
    print("=" * 65)
    print(f"  RAPPORT — {total} candidats en {elapsed:.0f}s  ({elapsed/max(total,1):.1f}s/article)")
    print("=" * 65)
    print(f"  PRE_FILTERED          : {counts['PRE_FILTERED']:>5}  (0 appel API)")
    print(f"  LLM_DONE (pertinent)  : {counts['LLM_DONE']:>5}  → {items_created} items PENDING créés")
    print(f"  LLM_DONE (hors scope) : {counts['LLM_DONE_NOT_PERTINENT']:>5}")
    print(f"  LLM_FAILED            : {counts['LLM_FAILED']:>5}")
    print(f"  Appels Claude réels   : {llm_calls:>5}")
    if input_tokens:
        print(f"  Tokens input/output   : {input_tokens:,} / {output_tokens:,}")
        print(f"  Coût estimé Haiku     : ${cost_usd:.4f}")
    print()

    if scores:
        dist: dict[str, int] = defaultdict(int)
        for sc in scores:
            if sc >= 7:
                dist["7-10"] += 1
            elif sc >= 4:
                dist["4-6"] += 1
            else:
                dist["1-3"] += 1
        print(f"  Score density — min={min(scores)} max={max(scores)} moy={sum(scores)/len(scores):.1f}")
        print(f"  Distribution : 7-10: {dist['7-10']}  4-6: {dist['4-6']}  1-3: {dist['1-3']}")
        print()

    errors = [r for r in reports if r.get("status") == "LLM_FAILED"]
    if errors:
        print(f"  Erreurs ({len(errors)}) :")
        for e in errors[:5]:
            print(f"    [{e.get('candidate_id','')[:8]}] {e.get('error','')[:80]}")
        if len(errors) > 5:
            print(f"    ... et {len(errors)-5} autres")

    # 3 exemples d'items créés
    pertinents = [r for r in reports if r.get("status") == "LLM_DONE"][:3]
    if pertinents:
        print()
        print("  Exemples d'articles retenus :")
        for r in pertinents:
            print(f"    score={r.get('score_density')} [{r.get('audience','')}] {r.get('title','')[:70]}")

    print("=" * 65)


async def main_async(limit: int, yes: bool) -> None:
    remaining_before = count_remaining()
    effective = min(limit, remaining_before)

    print(f"Candidats NEW/LLM_FAILED en base : {remaining_before}")
    print(f"Ce batch : {effective} candidats  |  MAX_CONCURRENT={MAX_CONCURRENT}  |  Modèle={ANTHROPIC_MODEL}")
    print()

    if remaining_before == 0:
        print("Aucun candidat à traiter.")
        return

    candidates = fetch_batch(limit)
    if not candidates:
        print("Aucun candidat récupéré.")
        return

    print(f"Démarrage — {datetime.now().strftime('%H:%M:%S')}")
    print()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    counter   = [0]  # mutable pour accès depuis coroutines
    total     = len(candidates)

    t0 = time.time()
    tasks = [_process_async(c, semaphore, counter, total) for c in candidates]
    reports = await asyncio.gather(*tasks, return_exceptions=False)

    elapsed = time.time() - t0
    print_report(list(reports), elapsed)

    remaining_after = count_remaining()
    print(f"\nRestant en base : {remaining_after} candidats NEW/LLM_FAILED")

    if remaining_after > 0:
        cmd = f"python scripts/run_llm_analysis.py --limit {remaining_after}"
        if yes:
            print(f"\n--yes activé. Pour lancer les {remaining_after} restants :")
            print(f"  {cmd} --yes")
        else:
            print(f"\nPour lancer les {remaining_after} restants :")
            print(f"  {cmd}")
    else:
        print("\nTous les candidats ont été traités.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse LLM async (Claude Haiku)")
    parser.add_argument("--limit", type=int, default=100, help="Nombre de candidats à traiter")
    parser.add_argument("--yes", action="store_true", help="Pas de pause pour confirmer")
    args = parser.parse_args()
    asyncio.run(main_async(args.limit, args.yes))


if __name__ == "__main__":
    main()
