# app/scheduler.py
"""
Automatisation mensuelle complète du pipeline.

JOBS :
  Jour 1  06h UTC  → job_collect_and_analyse()
      1. JORF via PISTE (fonds existant)
      2. KALI / LEGI / CIRCULAIRES via PISTE (nouveaux fonds)
      3. HAS / ANSM / Santé publique France via RSS
      4. Analyse Claude sur tous les candidats NEW

  Jour 7  08h UTC  → job_send_newsletters()
      Compile + envoie 1 email par spécialité (items APPROVED uniquement)

ACTIVATION : SCHEDULER_ENABLED=true dans .env
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import date, timedelta
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.db import get_conn
from app.security import decrypt_email
from app.mailer import send_bulk
from app.newsletter_builder import build_newsletter, SPECIALTY_LABELS

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


# ---------------------------------------------------------------------------
# JOB 1 — Collecte toutes sources + analyse LLM
# ---------------------------------------------------------------------------

def job_collect_and_analyse() -> None:
    logger.info("=" * 60)
    logger.info("JOB COLLECTE démarré — %s", date.today().isoformat())
    logger.info("=" * 60)

    report: dict[str, Any] = {}

    # ── 1. JORF (pipeline existant) ──────────────────────────────
    try:
        from app.piste_routes import (
            _piste_call, _extract_list, _keep_item_with_reason,
            _parse_date10, _official_url, _sha256_hex, _json_canonical_bytes,
        )
        from app.collector_utils import build_candidate_row, insert_candidate
        from psycopg.types.json import Json

        source = "legifrance_jorf"
        today = date.today()
        start = today - timedelta(days=35)
        page_size, max_pages = 50, 40
        seen = ins = dup = 0

        with get_conn() as conn:
            with conn.cursor() as cur:
                for page in range(1, max_pages + 1):
                    payload = {"fond": "JORF", "recherche": {
                        "pageNumber": page, "pageSize": page_size,
                        "operateur": "ET", "typePagination": "DEFAUT",
                        "filtres": [{"facette": "DATE_PUBLICATION", "dates": {
                            "start": start.strftime("%Y-%m-%dT00:00:00.000+0000"),
                            "end": today.strftime("%Y-%m-%dT23:59:59.000+0000"),
                        }}],
                    }}
                    try:
                        data = _piste_call("/search", payload)
                    except Exception:
                        break
                    items = _extract_list(data)
                    if not items:
                        break
                    for it in items:
                        if not isinstance(it, dict):
                            continue
                        seen += 1
                        titles = it.get("titles") if isinstance(it.get("titles"), list) else []
                        t0 = titles[0] if titles and isinstance(titles[0], dict) else {}
                        jorftext_id = t0.get("cid")
                        title = t0.get("title")
                        nature = it.get("nature") or it.get("type")
                        ok, _ = _keep_item_with_reason(nature, title)
                        if not ok:
                            continue
                        pub_s = _parse_date10(it.get("datePublication")) or _parse_date10(it.get("date"))
                        if not pub_s:
                            continue
                        pub_d = date.fromisoformat(pub_s)
                        if not (start <= pub_d <= today):
                            continue
                        if not (isinstance(jorftext_id, str) and jorftext_id.startswith("JORFTEXT")):
                            continue
                        row = build_candidate_row(
                            source=source, external_id=jorftext_id,
                            official_url=_official_url(jorftext_id),
                            official_date=pub_d, title_raw=(title or "").strip() or "(no title)",
                            jorftext_id=jorftext_id, raw_payload=it,
                        )
                        if insert_candidate(cur, row):
                            ins += 1
                        else:
                            dup += 1
            conn.commit()

        report["jorf"] = {"seen": seen, "inserted": ins, "deduped": dup}
        logger.info("JORF : vu=%d ins=%d dup=%d", seen, ins, dup)
    except Exception as e:
        logger.error("JORF échoué : %s", e)
        report["jorf"] = {"error": str(e)}

    # ── 2. KALI / LEGI / CIRCULAIRES ─────────────────────────────
    try:
        from app.piste_routes import EXTRA_FONDS
        from app.db import get_conn as _get_conn
        extra_report: dict[str, Any] = {}
        for fond, src in EXTRA_FONDS.items():
            try:
                today_d = date.today()
                start_d = today_d - timedelta(days=35)
                from app.piste_routes import _piste_call as pc, _extract_list as el, _parse_date10 as pd10, _sha256_hex as sh, _json_canonical_bytes as jcb
                ins = dup = s = 0
                insert_sql = """
                INSERT INTO candidates (source, official_url, official_date, title_raw, content_raw, raw_sha256, dedupe_key, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'NEW') ON CONFLICT (dedupe_key) DO NOTHING;
                """
                with _get_conn() as conn:
                    with conn.cursor() as cur:
                        for pg in range(1, 21):
                            data = pc("/search", {"fond": fond, "recherche": {"pageNumber": pg, "pageSize": 50, "operateur": "ET", "typePagination": "DEFAUT", "filtres": [{"facette": "DATE_PUBLICATION", "dates": {"start": start_d.strftime("%Y-%m-%dT00:00:00.000+0000"), "end": today_d.strftime("%Y-%m-%dT23:59:59.000+0000")}}]}})
                            items = el(data) if isinstance(data, dict) else []
                            if not items:
                                break
                            for it in items:
                                if not isinstance(it, dict):
                                    continue
                                s += 1
                                titles = it.get("titles") if isinstance(it.get("titles"), list) else []
                                t0 = titles[0] if titles and isinstance(titles[0], dict) else {}
                                text_id = t0.get("cid") or it.get("id") or ""
                                title = t0.get("title") or "(no title)"
                                pub_s = pd10(it.get("datePublication")) or pd10(it.get("date"))
                                if not pub_s:
                                    continue
                                pub_d_val = date.fromisoformat(pub_s)
                                if not (start_d <= pub_d_val <= today_d):
                                    continue
                                dk = sh(f"{src}|{text_id}".encode())
                                rs = sh(jcb(it))
                                cur.execute(insert_sql, (src, f"https://www.legifrance.gouv.fr/{fond.lower()}/id/{text_id}", pub_d_val, title.strip(), None, rs, dk))
                                if cur.rowcount == 1:
                                    ins += 1
                                else:
                                    dup += 1
                    conn.commit()
                extra_report[fond] = {"seen": s, "inserted": ins, "deduped": dup}
                logger.info("%s : vu=%d ins=%d dup=%d", fond, s, ins, dup)
            except Exception as e2:
                logger.error("%s échoué : %s", fond, e2)
                extra_report[fond] = {"error": str(e2)}
        report["piste_extra"] = extra_report
    except Exception as e:
        logger.error("PISTE extra fonds échoués : %s", e)
        report["piste_extra"] = {"error": str(e)}

    # ── 3. RSS (HAS / ANSM / SPF) ────────────────────────────────
    try:
        from app.rss_collector import collect_all_rss
        report["rss"] = collect_all_rss(days=35)
    except Exception as e:
        logger.error("RSS collecte échouée : %s", e)
        report["rss"] = {"error": str(e)}

    # ── 4. Analyse LLM sur tous les NEW ──────────────────────────
    try:
        _run_llm_batch()
    except Exception as e:
        logger.error("Analyse LLM échouée : %s", e)

    logger.info("=" * 60)
    logger.info("JOB COLLECTE terminé")
    logger.info("=" * 60)
    return report


def _run_llm_batch() -> None:
    from app.llm_routes import _fetch_candidates_to_analyse, _process_one_candidate

    with get_conn() as conn:
        with conn.cursor() as cur:
            candidates = _fetch_candidates_to_analyse(cur, None, limit=300)

    if not candidates:
        logger.info("LLM : aucun candidat NEW")
        return

    logger.info("LLM : %d candidats à analyser", len(candidates))
    done = failed = skipped = 0

    for candidate in candidates:
        r = _process_one_candidate(candidate)
        s = r.get("status", "")
        if s == "LLM_DONE":
            done += 1
        elif s == "LLM_DONE_NOT_PERTINENT":
            skipped += 1
        else:
            failed += 1

    logger.info("LLM : pertinents=%d non-pertinents=%d erreurs=%d", done, skipped, failed)


# ---------------------------------------------------------------------------
# JOB 2 — Envoi newsletters
# ---------------------------------------------------------------------------

def job_send_newsletters() -> None:
    logger.info("=" * 60)
    logger.info("JOB ENVOI NEWSLETTER démarré — %s", date.today().isoformat())
    logger.info("=" * 60)

    total_sent = total_failed = 0

    for slug in SPECIALTY_LABELS.keys():
        try:
            sent, failed = _send_specialty_newsletter(slug)
            total_sent += sent
            total_failed += failed
        except Exception as e:
            logger.error("Newsletter %s : %s", slug, e)

    logger.info("JOB ENVOI terminé : envoyés=%d erreurs=%d", total_sent, total_failed)


def _get_approved_items(specialty_slug: str) -> list[dict[str, Any]]:
    since = date.today() - timedelta(days=35)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                       i.tri_json, i.lecture_json,
                       c.title_raw, c.official_url, c.official_date::text
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'APPROVED'
                  AND c.official_date >= %s
                  AND (i.audience = 'TRANSVERSAL_LIBERAL' OR i.specialty_slug = %s)
                ORDER BY i.score_density DESC, c.official_date DESC;
            """, (since, specialty_slug))
            rows = cur.fetchall()
    return [
        {"item_id": str(r[0]), "audience": r[1], "specialty_slug": r[2],
         "score_density": r[3], "tri_json": r[4], "lecture_json": r[5],
         "title_raw": r[6], "official_url": r[7], "official_date": r[8]}
        for r in rows
    ]


def _get_subscribers(specialty_slug: str) -> list[str]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.email_ciphertext
                FROM users u
                WHERE u.specialty_id = %s AND u.email_verified_at IS NOT NULL;
            """, (specialty_slug,))
            rows = cur.fetchall()
    emails = []
    for (raw,) in rows:
        try:
            emails.append(decrypt_email(raw))
        except Exception:
            pass
    return emails


def _send_specialty_newsletter(specialty_slug: str) -> tuple[int, int]:
    items = _get_approved_items(specialty_slug)
    if not items:
        logger.info("Spécialité %s : aucun item approuvé", specialty_slug)
        return 0, 0
    subscribers = _get_subscribers(specialty_slug)
    if not subscribers:
        logger.info("Spécialité %s : aucun abonné", specialty_slug)
        return 0, 0
    logger.info("Spécialité %s : %d articles → %d abonnés", specialty_slug, len(items), len(subscribers))
    subject, html, plain = build_newsletter(
        specialty_slug=specialty_slug, items=items, emission_date=date.today()
    )
    result = send_bulk(subscribers, subject, html, plain)
    return result["sent"], result["failed"]


# ---------------------------------------------------------------------------
# JOB 3 — Nettoyage des tokens expirés (refresh + email verification)
# ---------------------------------------------------------------------------

def job_cleanup_tokens() -> None:
    """Supprime les refresh_tokens et email_verification_tokens expirés.

    Tourne chaque nuit à 03h00 UTC pour éviter l'accumulation en DB.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM refresh_tokens WHERE expires_at < now() - INTERVAL '1 day';"
            )
            rt_deleted = cur.rowcount
            cur.execute(
                "DELETE FROM email_verification_tokens WHERE expires_at < now() - INTERVAL '1 day';"
            )
            evt_deleted = cur.rowcount
    logger.info(
        "Cleanup tokens : %d refresh_tokens, %d email_verification_tokens supprimés",
        rt_deleted, evt_deleted,
    )


# ---------------------------------------------------------------------------
# Démarrage / arrêt
# ---------------------------------------------------------------------------

def start_scheduler() -> AsyncIOScheduler:
    global _scheduler

    collect_day  = int(os.environ.get("SCHEDULER_COLLECT_DAY", "1"))
    collect_hour = int(os.environ.get("SCHEDULER_COLLECT_HOUR", "6"))
    send_day     = int(os.environ.get("SCHEDULER_SEND_DAY", "7"))
    send_hour    = int(os.environ.get("SCHEDULER_SEND_HOUR", "8"))

    _scheduler = AsyncIOScheduler(timezone="UTC")

    _scheduler.add_job(
        job_collect_and_analyse,
        trigger=CronTrigger(day=collect_day, hour=collect_hour, minute=0),
        id="monthly_collect",
        name=f"Collecte complète + LLM (j={collect_day} h={collect_hour}h UTC)",
        executor='threadpool',
        replace_existing=True,
        misfire_grace_time=3600,
    )

    _scheduler.add_job(
        job_send_newsletters,
        trigger=CronTrigger(day=send_day, hour=send_hour, minute=0),
        id="monthly_send",
        name=f"Envoi newsletters (j={send_day} h={send_hour}h UTC)",
        executor='threadpool',
        replace_existing=True,
        misfire_grace_time=3600,
    )

    _scheduler.add_job(
        job_cleanup_tokens,
        trigger=CronTrigger(hour=3, minute=0),
        id="daily_cleanup",
        name="Nettoyage tokens expirés (03h00 UTC)",
        executor='threadpool',
        replace_existing=True,
        misfire_grace_time=3600,
    )

    _scheduler.start()
    logger.info(
        "Scheduler démarré — collecte j=%d h=%dh, envoi j=%d h=%dh (UTC)",
        collect_day, collect_hour, send_day, send_hour,
    )
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler arrêté")


@asynccontextmanager
async def lifespan(app: Any):
    enabled = os.environ.get("SCHEDULER_ENABLED", "false").lower() == "true"
    if enabled:
        start_scheduler()
    else:
        logger.info("Scheduler désactivé (SCHEDULER_ENABLED=false)")
    yield
    stop_scheduler()
