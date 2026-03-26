#!/usr/bin/env python3
"""
Backfill type_praticien sur les items APPROVED existants (type_praticien IS NULL).

Utilise un prompt ciblé (uniquement type_praticien) pour minimiser les tokens.
Traite les items par tranches de 20 avec concurrence limitée à 5 appels API.

Usage :
  python scripts/backfill_type_praticien.py              # dry-run (affiche sans modifier)
  python scripts/backfill_type_praticien.py --apply      # applique en base
  python scripts/backfill_type_praticien.py --apply --batch-size 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("✗ DATABASE_URL manquant dans .env")
    sys.exit(1)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import psycopg
import anthropic

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"
CONCURRENCY = 5          # appels API simultanés max
KNOWN_TYPE_PRATICIEN = {"prescripteur", "interventionnel", "biologiste", "pharmacien", "tous"}

# ---------------------------------------------------------------------------
# Prompt ciblé — uniquement type_praticien
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
Tu es un expert en réglementation médicale française.
On te donne le titre (et parfois un extrait) d'un texte réglementaire ou d'une alerte de sécurité \
publié dans le Journal Officiel, par l'ANSM, la HAS ou le Ministère de la Santé.

Détermine le profil professionnel PRINCIPALEMENT concerné par ce texte.
Réponds UNIQUEMENT avec un objet JSON contenant un seul champ "type_praticien".

Valeurs possibles :
- "prescripteur"    : médecins qui prescrivent des médicaments en ambulatoire \
(MG, internistes, cardiologues, pneumologues…). \
Exemples : alerte pharmacovigilance, nouvelle indication, remboursement médicament de ville.
- "interventionnel" : praticiens réalisant des actes techniques invasifs \
(chirurgiens, anesthésistes, radiologues interventionnels). \
Exemples : dispositifs implantables, prothèses, fils de suture, matériel de bloc, cotations CCAM.
- "biologiste"      : biologistes médicaux (analyses biologiques, réactifs, automates).
- "pharmacien"      : pharmaciens d'officine (substitution, ruptures de stock officine, \
convention pharmacien, dispensation).
- "tous"            : tous les professionnels de santé libéraux \
(convention médicale nationale, tiers-payant, exercice libéral général).

RÈGLE CLEF — Médicament vs dispositif :
  Alerte sur une MOLÉCULE/DCI/spécialité pharmaceutique  → "prescripteur"
  Alerte sur un DISPOSITIF IMPLANTABLE/prothèse/instrument chirurgical → "interventionnel"
  Texte sur des HONORAIRES/CCAM/convention générale → "tous"

Réponds UNIQUEMENT avec {"type_praticien": "<valeur>"}, sans texte autour.
"""

def _build_user_prompt(title: str, content: str | None) -> str:
    excerpt = ""
    if content and len(content.strip()) > 50:
        excerpt = f"\n\nEXTRAIT :\n{content.strip()[:1500]}"
    return f"TITRE : {title}{excerpt}\n\nJSON :"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def fetch_items_to_backfill(limit: int = 1000) -> list[dict]:
    """Retourne les items APPROVED sans type_praticien, triés par score desc."""
    conn = psycopg.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       c.title_raw, c.content_raw, c.source,
                       i.tri_json->>'titre_court' AS titre_court
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND i.type_praticien IS NULL
                ORDER BY i.score_density DESC
                LIMIT %s;
            """, (limit,))
            rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "item_id": str(r[0]),
            "audience": r[1],
            "specialty_slug": r[2],
            "score_density": r[3],
            "title_raw": r[4],
            "content_raw": r[5],
            "source": r[6],
            "titre_court": r[7],
        }
        for r in rows
    ]


def apply_updates(updates: list[dict]) -> int:
    """Applique les type_praticien en base. Retourne le nombre de lignes mises à jour."""
    if not updates:
        return 0
    conn = psycopg.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            updated = 0
            for u in updates:
                cur.execute(
                    "UPDATE items SET type_praticien = %s WHERE id = %s;",
                    (u["type_praticien"], u["item_id"]),
                )
                updated += cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return updated


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

async def _call_llm(client: anthropic.AsyncAnthropic, item: dict, sem: asyncio.Semaphore) -> dict:
    """Appel LLM ciblé pour obtenir uniquement type_praticien."""
    async with sem:
        title = item["titre_court"] or item["title_raw"] or "(sans titre)"
        user_prompt = _build_user_prompt(title, item.get("content_raw"))

        for attempt in range(3):
            try:
                resp = await client.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=60,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                raw = resp.content[0].text.strip()
                # Extraire JSON
                m = re.search(r'\{[^}]+\}', raw)
                if not m:
                    raise ValueError(f"Pas de JSON trouvé dans : {raw!r}")
                data = json.loads(m.group())
                tp = data.get("type_praticien", "").strip()
                if tp not in KNOWN_TYPE_PRATICIEN:
                    # Fallback basé sur audience/specialité
                    tp = _infer_fallback(item)
                return {"item_id": item["item_id"], "type_praticien": tp, "status": "ok"}

            except anthropic.RateLimitError:
                wait = 5 * (3 ** attempt)
                logger.warning("Rate limit (tentative %d/3) — attente %ds", attempt + 1, wait)
                await asyncio.sleep(wait)
            except Exception as e:
                if attempt == 2:
                    logger.error("Échec item %s : %s", item["item_id"], e)
                    return {"item_id": item["item_id"], "type_praticien": None, "status": f"error:{e}"}
                await asyncio.sleep(2 ** attempt)

        return {"item_id": item["item_id"], "type_praticien": None, "status": "exhausted"}


def _infer_fallback(item: dict) -> str:
    audience = item.get("audience", "")
    slug = item.get("specialty_slug", "") or ""
    if audience == "PHARMACIENS":
        return "pharmacien"
    if any(s in slug for s in ("chirurgie", "anesthesiologie", "neurochirurgie")):
        return "interventionnel"
    if audience == "TRANSVERSAL_LIBERAL":
        return "tous"
    return "prescripteur"


async def run_batch(items: list[dict], apply: bool, batch_size: int) -> list[dict]:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY manquante")
        sys.exit(1)

    client = anthropic.AsyncAnthropic(api_key=api_key)
    sem = asyncio.Semaphore(CONCURRENCY)
    all_results: list[dict] = []

    total = len(items)
    logger.info("━━━ Backfill type_praticien — %d items à traiter ━━━", total)
    logger.info("Mode : %s | batch_size=%d | concurrence=%d", "APPLY" if apply else "DRY-RUN", batch_size, CONCURRENCY)

    t0 = time.monotonic()

    for batch_start in range(0, total, batch_size):
        batch = items[batch_start : batch_start + batch_size]
        batch_num = batch_start // batch_size + 1
        logger.info("Batch %d/%d — %d items", batch_num, -(-total // batch_size), len(batch))

        tasks = [_call_llm(client, item, sem) for item in batch]
        results = await asyncio.gather(*tasks)

        ok = [r for r in results if r["type_praticien"] is not None]
        errors = [r for r in results if r["type_praticien"] is None]

        if apply and ok:
            updated = apply_updates(ok)
            logger.info("  → %d mis à jour en base, %d erreurs", updated, len(errors))
        else:
            logger.info("  → [DRY-RUN] %d résultats, %d erreurs", len(ok), len(errors))

        # Log chaque changement
        for item_orig, res in zip(batch, results):
            status_icon = "✓" if res["status"] == "ok" else "✗"
            tp = res["type_praticien"] or "ERREUR"
            logger.info(
                "  %s [%s→%s] score=%s  %s",
                status_icon,
                item_orig.get("audience", "?")[:4],
                tp[:14],
                item_orig.get("score_density", "?"),
                (item_orig.get("titre_court") or item_orig.get("title_raw", ""))[:60],
            )

        all_results.extend(results)

        # Pause courte entre batches pour ménager le rate limit
        if batch_start + batch_size < total:
            await asyncio.sleep(1)

    elapsed = time.monotonic() - t0
    ok_total = sum(1 for r in all_results if r["status"] == "ok")
    err_total = sum(1 for r in all_results if r["type_praticien"] is None)

    logger.info("━━━ Terminé en %.1fs — %d OK / %d erreurs ━━━", elapsed, ok_total, err_total)

    # Résumé par type_praticien
    from collections import Counter
    dist = Counter(r["type_praticien"] for r in all_results if r["type_praticien"])
    logger.info("Distribution : %s", dict(dist.most_common()))

    return all_results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Backfill type_praticien sur items APPROVED")
    parser.add_argument("--apply", action="store_true", help="Applique les mises à jour (défaut: dry-run)")
    parser.add_argument("--batch-size", type=int, default=20, help="Taille de chaque batch (défaut: 20)")
    parser.add_argument("--limit", type=int, default=1000, help="Nombre max d'items à traiter")
    args = parser.parse_args()

    logger.info("Chargement des items APPROVED sans type_praticien…")
    items = fetch_items_to_backfill(args.limit)
    logger.info("%d items trouvés", len(items))

    if not items:
        logger.info("Rien à faire.")
        return

    results = asyncio.run(run_batch(items, apply=args.apply, batch_size=args.batch_size))

    if not args.apply:
        print("\n⚠️  Mode dry-run — relancer avec --apply pour écrire en base.")
    else:
        # Vérification finale
        conn = psycopg.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM items WHERE review_status='APPROVED' AND type_praticien IS NULL;")
                remaining = cur.fetchone()[0]
        finally:
            conn.close()
        logger.info("Items APPROVED sans type_praticien restants : %d", remaining)


if __name__ == "__main__":
    main()
