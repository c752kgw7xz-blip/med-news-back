#!/usr/bin/env python3
"""
Pipeline manuel MedNews — collecte + pré-filtre + analyse LLM.

Sous-commandes :
    collect     Collecte les sources pour une spécialité (ou toutes)
    prefilter   Élimine les candidats hors-scope sans appel LLM (heuristiques)
    llm         Analyse les candidats restants avec Claude

Workflow spé par spé :
    python scripts/pipeline.py collect --specialty cardiologie --days 180
    python scripts/pipeline.py prefilter
    python scripts/pipeline.py llm --limit 200

Collecte globale :
    python scripts/pipeline.py collect --all --days 180
    python scripts/pipeline.py prefilter
    python scripts/pipeline.py llm --limit 500

Spécialités disponibles (37) :
    anesthesiologie, biologiste, cardiologie, chirurgie-cardiaque,
    chirurgie-orthopedique, chirurgie-pediatrique, chirurgie-plastique,
    chirurgie-thoracique, chirurgie-vasculaire, dentiste, dermatologie,
    endocrinologie, gastro-enterologie, geriatrie, gynecologie,
    hematologie, infectiologie, infirmiers, kinesitherapie,
    medecine-generale, medecine-interne, medecine-physique, medecine-urgences,
    nephrologie, neurochirurgie, neurologie, oncologie, ophtalmologie,
    orl, pediatrie, pharmacien, pneumologie, psychiatrie, radiologie,
    rhumatologie, sage-femme, urologie
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env", override=True)

import psycopg
from psycopg.types.json import Json

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("❌  DATABASE_URL manquant dans .env")
    sys.exit(1)


def get_conn():
    return psycopg.connect(DATABASE_URL)


# ─────────────────────────────────────────────────────────────────────────────
# Sous-commande : collect
# ─────────────────────────────────────────────────────────────────────────────

def _valid_specialties() -> set[str]:
    from app.sources import ALL_FEEDS, API_SOURCES
    from app.pubmed_collector import PUBMED_SOURCES
    hints: set[str] = set()
    for src in (*ALL_FEEDS, *PUBMED_SOURCES, *API_SOURCES):
        h = src.get("specialty_hint", "")
        if h and h != "tous":
            hints.add(h)
    return hints


def _print_collect_report(report: dict, elapsed: float) -> None:
    def _section_stats(section: dict) -> tuple[int, int, int]:
        inserted = skipped = errors = 0
        for r in section.values():
            if isinstance(r, dict):
                if "error" in r and len(r) == 1:
                    errors += 1
                else:
                    inserted += r.get("inserted", 0)
                    skipped  += r.get("skipped", 0)
        return inserted, skipped, errors

    total_inserted = 0
    for key in ("rss", "pubmed", "web", "api"):
        section = report.get(key)
        if not section or not isinstance(section, dict):
            continue
        ins, skp, err = _section_stats(section)
        total_inserted += ins
        sources_ok  = sum(1 for r in section.values() if isinstance(r, dict) and "error" not in r)
        sources_err = sum(1 for r in section.values() if isinstance(r, dict) and "error" in r and len(r) == 1)
        label = key.upper()
        print(f"  {label:<8}  {sources_ok} sources  →  {ins:>4} insérés  {skp:>4} doublons"
              + (f"  {sources_err} erreurs" if sources_err else ""))
        if sources_err:
            for src, r in section.items():
                if isinstance(r, dict) and "error" in r and len(r) == 1:
                    print(f"           ✗ {src}: {r['error'][:80]}")

    print(f"\n  Total inséré  : {total_inserted} nouveaux candidats  ({elapsed:.0f}s)")


def cmd_collect(args: argparse.Namespace) -> None:
    from app.collector import collect_by_specialty_sources, collect_all

    days = args.days

    if args.all:
        print(f"Collecte globale — fenêtre {days}j…\n")
        t0 = time.time()
        report = collect_all(days=days)
        _print_collect_report(report, time.time() - t0)
        return

    slug = args.specialty
    valid = _valid_specialties()
    if slug not in valid:
        print(f"❌  Spécialité inconnue : '{slug}'")
        print(f"   Valeurs valides :\n   " + "\n   ".join(sorted(valid)))
        sys.exit(1)

    print(f"Collecte [{slug}] — fenêtre {days}j…\n")
    t0 = time.time()
    report = collect_by_specialty_sources(slug, days=days)
    _print_collect_report(report, time.time() - t0)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status = 'NEW';")
            total_new = cur.fetchone()[0]
    print(f"  Candidats NEW en base (toutes spés) : {total_new}")
    print(f"\nÉtape suivante :")
    print(f"  python scripts/pipeline.py prefilter")
    print(f"  python scripts/pipeline.py llm")


# ─────────────────────────────────────────────────────────────────────────────
# Sous-commande : prefilter
# ─────────────────────────────────────────────────────────────────────────────

def cmd_prefilter(args: argparse.Namespace) -> None:
    from app.llm_analysis import pre_filter_candidate

    print(f"{'[DRY-RUN] ' if args.dry_run else ''}Connexion à Neon DB…")
    t0 = time.time()

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status = 'NEW';")
            total_new = cur.fetchone()[0]

        print(f"📊  {total_new} candidats NEW à traiter (batch={args.batch})\n")

        eliminated = kept = batch_n = 0
        last_id = "00000000-0000-0000-0000-000000000000"

        while True:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, title_raw, source
                    FROM candidates
                    WHERE status = 'NEW' AND id > %s::uuid
                    ORDER BY id LIMIT %s;
                    """,
                    (last_id, args.batch),
                )
                rows = cur.fetchall()

            if not rows:
                break

            batch_n += 1
            last_id = str(rows[-1][0])
            to_eliminate: list[str] = []

            for (cid, title_raw, source) in rows:
                keep, _ = pre_filter_candidate(title_raw or "", source=source or "")
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


# ─────────────────────────────────────────────────────────────────────────────
# Sous-commande : llm
# ─────────────────────────────────────────────────────────────────────────────

MAX_CONCURRENT = 3

INSERT_ITEM_SQL = """
INSERT INTO items (
    candidate_id, audience, specialty_slug,
    tri_json, lecture_json, score_density,
    categorie, type_praticien, source_type,
    evidence_json, llm_raw, llm_model, review_status
)
VALUES (
    %(candidate_id)s, %(audience)s, %(specialty_slug)s,
    %(tri_json)s, %(lecture_json)s, %(score_density)s,
    %(categorie)s, %(type_praticien)s, %(source_type)s,
    %(evidence_json)s, %(llm_raw)s, %(llm_model)s, 'PENDING'
)
ON CONFLICT (candidate_id, COALESCE(specialty_slug, '')) DO NOTHING
RETURNING id;
"""


def _fetch_batch(limit: int | None) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            if limit:
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
            else:
                cur.execute(
                    """
                    SELECT id, title_raw, content_raw, official_date::text, source
                    FROM candidates
                    WHERE status IN ('NEW', 'LLM_FAILED')
                    ORDER BY official_date DESC;
                    """
                )
            rows = cur.fetchall()
    return [
        {"id": str(r[0]), "title_raw": r[1], "content_raw": r[2],
         "official_date": r[3], "source": r[4] or ""}
        for r in rows
    ]


def _count_remaining() -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM candidates WHERE status IN ('NEW', 'LLM_FAILED')")
            return cur.fetchone()[0]


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
    from app.llm_analysis import get_source_config, get_source_type, ANTHROPIC_MODEL

    global_score        = result.get("score_density", 0)
    score_par_specialite: dict = result.get("score_par_specialite", {})
    audience            = result.get("audience", "SPECIALITE")
    if audience not in ("SPECIALITE", "PHARMACIENS"):
        audience = "SPECIALITE"
    specialites = result.get("specialites", [])
    llm_raw     = json.dumps(result, ensure_ascii=False)
    source_type = get_source_type(source)
    min_score   = get_source_config(source).get("min_llm_score", 5)

    if not result.get("pertinent", True) or global_score < min_score:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;", (cid,))
        return []

    slugs = ["pharmacien"] if audience == "PHARMACIENS" else (specialites or ["medecine-generale"])
    ev    = result.get("evidence_json")

    item_ids: list[str] = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            for slug in slugs:
                item_score = score_par_specialite.get(slug, global_score) if slug else global_score
                params = {
                    "candidate_id": cid, "audience": audience, "specialty_slug": slug,
                    "tri_json": Json(result.get("tri_json", {})),
                    "lecture_json": Json(result.get("lecture_json", {})),
                    "score_density": item_score, "categorie": result.get("categorie"),
                    "type_praticien": result.get("type_praticien"),
                    "source_type": source_type,
                    "evidence_json": Json(ev) if ev else None,
                    "llm_raw": llm_raw, "llm_model": result.get("llm_model", ANTHROPIC_MODEL),
                }
                cur.execute(INSERT_ITEM_SQL, params)
                row = cur.fetchone()
                if row:
                    item_ids.append(str(row[0]))
            cur.execute("UPDATE candidates SET status = 'LLM_DONE' WHERE id = %s;", (cid,))
    return item_ids


def _print_progress(n: int, total: int, cid: str, status: str, detail: str) -> None:
    print(f"  [{n:>4}/{total}] {status:<26} {cid[:8]}  {detail[:60]}", flush=True)


async def _process_async(candidate: dict, semaphore: asyncio.Semaphore, counter: list, total: int) -> dict:
    from app.llm_analysis import analyse_candidate_async, pre_filter_candidate

    cid   = candidate["id"]
    title = candidate["title_raw"]
    report: dict = {"candidate_id": cid, "title": title[:80]}

    keep, drop_reason = pre_filter_candidate(title, source=candidate.get("source"))
    if not keep:
        _db_mark_filtered(cid)
        report["status"] = "PRE_FILTERED"
        report["drop_reason"] = drop_reason
        counter[0] += 1
        _print_progress(counter[0], total, cid, "PRE_FILTERED", drop_reason or "")
        return report

    async with semaphore:
        try:
            result = await analyse_candidate_async(
                candidate_id=cid, title_raw=title,
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

    from app.llm_analysis import get_source_config
    score     = result.get("score_density", 0)
    pertinent = result.get("pertinent", True)
    item_ids  = _db_insert_result(cid, result, source=candidate.get("source"))
    min_score = get_source_config(candidate.get("source")).get("min_llm_score", 5)

    if not pertinent or score < min_score:
        report["status"] = "LLM_DONE_NOT_PERTINENT"
    else:
        report.update({"status": "LLM_DONE", "pertinent": True,
                       "audience": result.get("audience"),
                       "specialites": result.get("specialites", []),
                       "item_ids": item_ids})
    report["score_density"] = score

    counter[0] += 1
    suffix = f"score={score} items={len(item_ids)}" if item_ids else f"score={score}"
    _print_progress(counter[0], total, cid, report["status"], suffix)
    return report


def _print_report(reports: list[dict], elapsed: float) -> None:
    from app.llm_analysis import ANTHROPIC_MODEL

    counts: dict[str, int] = defaultdict(int)
    scores: list[int] = []
    for r in reports:
        counts[r.get("status", "?")] += 1
        if "score_density" in r:
            scores.append(r["score_density"])

    total        = len(reports)
    llm_calls    = counts["LLM_DONE"] + counts["LLM_DONE_NOT_PERTINENT"] + counts["LLM_FAILED"]
    items_created = sum(len(r.get("item_ids", [])) for r in reports)

    print()
    print("=" * 65)
    print(f"  RAPPORT — {total} candidats en {elapsed:.0f}s  ({elapsed/max(total,1):.1f}s/article)")
    print("=" * 65)
    print(f"  PRE_FILTERED          : {counts['PRE_FILTERED']:>5}  (0 appel API)")
    print(f"  LLM_DONE (pertinent)  : {counts['LLM_DONE']:>5}  → {items_created} items PENDING créés")
    print(f"  LLM_DONE (hors scope) : {counts['LLM_DONE_NOT_PERTINENT']:>5}")
    print(f"  LLM_FAILED            : {counts['LLM_FAILED']:>5}")
    print(f"  Appels Claude réels   : {llm_calls:>5}  (modèle: {ANTHROPIC_MODEL})")
    print()

    if scores:
        dist: dict[str, int] = defaultdict(int)
        for sc in scores:
            dist["7-10" if sc >= 7 else ("4-6" if sc >= 4 else "1-3")] += 1
        print(f"  Score density — min={min(scores)} max={max(scores)} moy={sum(scores)/len(scores):.1f}")
        print(f"  Distribution : 7-10: {dist['7-10']}  4-6: {dist['4-6']}  1-3: {dist['1-3']}")
        print()

    errors = [r for r in reports if r.get("status") == "LLM_FAILED"]
    if errors:
        print(f"  Erreurs ({len(errors)}) :")
        for e in errors[:5]:
            print(f"    [{e.get('candidate_id','')[:8]}] {e.get('error','')[:80]}")

    pertinents = [r for r in reports if r.get("status") == "LLM_DONE"][:3]
    if pertinents:
        print()
        print("  Exemples d'articles retenus :")
        for r in pertinents:
            print(f"    score={r.get('score_density')} [{r.get('audience','')}] {r.get('title','')[:70]}")

    print("=" * 65)


async def _llm_async(limit: int | None, yes: bool) -> None:
    remaining_before = _count_remaining()
    n_to_process = min(limit, remaining_before) if limit else remaining_before
    print(f"Candidats NEW/LLM_FAILED en base : {remaining_before}")
    print(f"Ce batch : {n_to_process} candidats  |  MAX_CONCURRENT={MAX_CONCURRENT}")
    print()

    if remaining_before == 0:
        print("Aucun candidat à traiter.")
        return

    candidates = _fetch_batch(limit)
    if not candidates:
        print("Aucun candidat récupéré.")
        return

    print(f"Démarrage — {datetime.now().strftime('%H:%M:%S')}\n")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    counter   = [0]
    total     = len(candidates)
    t0        = time.time()

    tasks   = [_process_async(c, semaphore, counter, total) for c in candidates]
    reports = await asyncio.gather(*tasks, return_exceptions=False)

    _print_report(list(reports), time.time() - t0)

    remaining_after = _count_remaining()
    if remaining_after > 0:
        print(f"\nRestant en base : {remaining_after} candidats NEW/LLM_FAILED")
    else:
        print(f"\nTous les candidats traités.")


def cmd_llm(args: argparse.Namespace) -> None:
    asyncio.run(_llm_async(args.limit, args.yes))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline MedNews — pré-filtre + analyse LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_col = sub.add_parser("collect", help="Collecte les sources (par spécialité ou globale)")
    grp = p_col.add_mutually_exclusive_group(required=True)
    grp.add_argument("--specialty", metavar="SLUG", help="Slug de spécialité (ex: cardiologie)")
    grp.add_argument("--all", action="store_true", help="Collecte toutes les sources")
    p_col.add_argument("--days", type=int, default=180, help="Fenêtre temporelle en jours (défaut: 180)")

    p_pre = sub.add_parser("prefilter", help="Élimine les candidats hors-scope (0 LLM)")
    p_pre.add_argument("--batch", type=int, default=500, help="Taille de lot (défaut 500)")
    p_pre.add_argument("--dry-run", action="store_true", help="Simulation sans écriture DB")

    p_llm = sub.add_parser("llm", help="Analyse LLM async (Claude)")
    p_llm.add_argument("--limit", type=int, default=None, help="Nombre max de candidats (défaut: tous)")
    p_llm.add_argument("--yes", action="store_true", help="Sans confirmation")

    args = parser.parse_args()
    if args.cmd == "collect":
        cmd_collect(args)
    elif args.cmd == "prefilter":
        cmd_prefilter(args)
    elif args.cmd == "llm":
        cmd_llm(args)


if __name__ == "__main__":
    main()
