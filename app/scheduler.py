# app/scheduler.py
"""
Pipeline automatisé — deux cadences distinctes :

  RÉGLEMENTATION  (mensuel — 1er du mois)
  ─────────────────────────────────────────
  Jour 1  06h UTC  → job_collect_regulation()
      Sources : JORF, KALI, LEGI, CIRCULAIRES, ANSM, BO Social
      Analyse Claude → items PENDING
  Quotidien 09h UTC → job_try_send_regulation()
      Si 0 article PENDING de type réglementaire ET
      newsletter pas encore envoyée ce mois-ci → envoi

  RECOMMANDATIONS (hebdomadaire — chaque lundi)
  ─────────────────────────────────────────────
  Lundi   06h UTC  → job_collect_recommendations()
      Sources : HAS RSS, sociétés savantes, ANSM bon usage
      Analyse Claude → items PENDING
  Quotidien 09h UTC → job_try_send_recommendations()
      Si 0 article PENDING de type recommandation ET
      newsletter pas encore envoyée cette semaine → envoi
      Fenêtre : articles des 7 derniers jours uniquement

  MAINTENANCE
  ─────────────────────────────────────────────
  Quotidien 03h UTC → job_cleanup_tokens()

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

# source_types réglementaires (mensuel)
REGULATION_SOURCE_TYPES = ("reglementaire", "therapeutique")
# source_types recommandations (hebdomadaire)
RECOMMENDATION_SOURCE_TYPES = ("recommandation",)


# ---------------------------------------------------------------------------
# Helpers DB — gestion newsletter_sends
# ---------------------------------------------------------------------------

def _count_pending(source_types: tuple[str, ...] | None = None) -> int:
    """Compte les items PENDING, optionnellement filtrés par source_type."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            if source_types:
                placeholders = ", ".join(["%s"] * len(source_types))
                cur.execute(
                    f"SELECT COUNT(*) FROM items WHERE review_status = 'PENDING' "
                    f"AND source_type IN ({placeholders});",
                    source_types,
                )
            else:
                cur.execute("SELECT COUNT(*) FROM items WHERE review_status = 'PENDING';")
            return cur.fetchone()[0]


def _newsletter_already_sent(newsletter_type: str, period_label: str) -> bool:
    """Vérifie si la newsletter a déjà été envoyée pour cette période."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM newsletter_sends WHERE newsletter_type = %s AND period_label = %s;",
                (newsletter_type, period_label),
            )
            return cur.fetchone() is not None


def _record_newsletter_sent(newsletter_type: str, period_label: str, articles_sent: int = 0) -> None:
    """Enregistre l'envoi de la newsletter pour cette période."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO newsletter_sends (newsletter_type, period_label, articles_sent)
                VALUES (%s, %s, %s)
                ON CONFLICT (newsletter_type, period_label) DO UPDATE
                  SET sent_at = now(), articles_sent = EXCLUDED.articles_sent;
                """,
                (newsletter_type, period_label, articles_sent),
            )


def _regulation_period() -> str:
    """Label de la période mensuelle réglementation, ex. '2026-03'."""
    return date.today().strftime("%Y-%m")


def _recommendation_period() -> str:
    """Label de la semaine ISO courante, ex. '2026-W12'."""
    today = date.today()
    iso = today.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


# ---------------------------------------------------------------------------
# JOB 1a — Collecte réglementation (1er du mois)
# ---------------------------------------------------------------------------

def job_collect_regulation() -> None:
    logger.info("=" * 60)
    logger.info("JOB COLLECTE RÉGLEMENTATION démarré — %s", date.today().isoformat())
    logger.info("=" * 60)

    report: dict[str, Any] = {}

    # ── 1. JORF ──────────────────────────────────────────────────
    try:
        from app.piste_routes import (
            _piste_call, _extract_list, _keep_item_with_reason,
            _parse_date10, _official_url, _sha256_hex, _json_canonical_bytes,
        )
        from app.collector_utils import build_candidate_row, insert_candidate

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
                INSERT INTO candidates (source, official_url, official_date, title_raw, content_raw, raw_json, raw_sha256, dedupe_key, status)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, 'NEW') ON CONFLICT (dedupe_key) DO NOTHING;
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
                                import json as _json
                                dk = sh(f"{src}|{text_id}".encode())
                                rs = sh(jcb(it))
                                cur.execute(insert_sql, (src, f"https://www.legifrance.gouv.fr/{fond.lower()}/id/{text_id}", pub_d_val, title.strip(), None, _json.dumps(it, ensure_ascii=False), rs, dk))
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

    # ── 3. RSS réglementaires uniquement (ANSM + BO Social) ──────
    try:
        from app.rss_collector import collect_ansm, collect_feed, FEEDS
        from app.llm_analysis import SOURCE_TO_TYPE

        report["ansm"] = collect_ansm(days=35)

        # BO Social et CNOM depuis FEEDS, filtrés sur source_type = reglementaire
        reg_sources = {s for s, t in SOURCE_TO_TYPE.items() if t == "reglementaire"}
        for feed in FEEDS:
            if feed["source"] in reg_sources and not feed["source"].startswith("ansm"):
                try:
                    r = collect_feed(feed, days=35)
                    report[feed["source"]] = r
                    logger.info("[%s] ins=%d", feed["source"], r.get("inserted", 0))
                except Exception as e3:
                    logger.error("[%s] erreur : %s", feed["source"], e3)
    except Exception as e:
        logger.error("RSS réglementation échoué : %s", e)
        report["rss_regulation"] = {"error": str(e)}

    # ── 4. Analyse LLM ───────────────────────────────────────────
    try:
        _run_llm_batch()
    except Exception as e:
        logger.error("Analyse LLM échouée : %s", e)

    logger.info("JOB COLLECTE RÉGLEMENTATION terminé")
    return report


# ---------------------------------------------------------------------------
# JOB 1b — Collecte recommandations (chaque lundi)
# ---------------------------------------------------------------------------

def job_collect_recommendations() -> None:
    logger.info("=" * 60)
    logger.info("JOB COLLECTE RECOMMANDATIONS démarré — %s", date.today().isoformat())
    logger.info("=" * 60)

    report: dict[str, Any] = {}

    # ── HAS + sociétés savantes (RSS) ────────────────────────────
    try:
        from app.rss_collector import collect_has, collect_pratique
        report["has"] = collect_has(days=10)           # légère marge > 7 jours
        report["pratique"] = collect_pratique(days=10)
        logger.info("Recommandations RSS collectées")
    except Exception as e:
        logger.error("RSS recommandations échoué : %s", e)
        report["rss"] = {"error": str(e)}

    # ── HAS CT (avis médicaments — source_type=therapeutique) ────
    try:
        from app.rss_collector import collect_feed, FEEDS
        for feed in FEEDS:
            if feed["source"] == "has_ct":
                r = collect_feed(feed, days=10)
                report["has_ct"] = r
                logger.info("[has_ct] ins=%d", r.get("inserted", 0))
    except Exception as e:
        logger.error("has_ct échoué : %s", e)

    # ── Analyse LLM ──────────────────────────────────────────────
    try:
        _run_llm_batch()
    except Exception as e:
        logger.error("Analyse LLM recommandations échouée : %s", e)

    logger.info("JOB COLLECTE RECOMMANDATIONS terminé")
    return report


# ---------------------------------------------------------------------------
# LLM batch (partagé)
# ---------------------------------------------------------------------------

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
# JOB 2a — Auto-envoi newsletter réglementation (vérification quotidienne)
# ---------------------------------------------------------------------------

def job_try_send_regulation() -> None:
    """
    Vérifie chaque jour si la newsletter réglementation peut être envoyée :
    - Aucun item PENDING de type réglementaire/thérapeutique
    - Newsletter pas encore envoyée ce mois-ci
    Si oui : envoie et enregistre.
    """
    period = _regulation_period()

    if _newsletter_already_sent("reglementaire", period):
        logger.info("Newsletter réglementation %s déjà envoyée — skip", period)
        return

    pending = _count_pending(REGULATION_SOURCE_TYPES)
    if pending > 0:
        logger.info(
            "Newsletter réglementation %s : %d article(s) encore en attente de review — report",
            period, pending,
        )
        return

    logger.info(
        "Newsletter réglementation %s : 0 PENDING — déclenchement de l'envoi", period
    )
    total_sent = _send_newsletters_by_source_type(
        source_types=REGULATION_SOURCE_TYPES,
        days=35,
    )
    _record_newsletter_sent("reglementaire", period, articles_sent=total_sent)
    logger.info("Newsletter réglementation envoyée : %d articles au total", total_sent)


# ---------------------------------------------------------------------------
# JOB 2b — Auto-envoi newsletter recommandations (vérification quotidienne)
# ---------------------------------------------------------------------------

def job_try_send_recommendations() -> None:
    """
    Vérifie chaque jour si la newsletter recommandations peut être envoyée :
    - Aucun item PENDING de type recommandation
    - Newsletter pas encore envoyée cette semaine
    Si oui : envoie (fenêtre = 7 derniers jours uniquement).
    """
    period = _recommendation_period()

    if _newsletter_already_sent("recommandation", period):
        logger.info("Newsletter recommandations %s déjà envoyée — skip", period)
        return

    pending = _count_pending(RECOMMENDATION_SOURCE_TYPES)
    if pending > 0:
        logger.info(
            "Newsletter recommandations %s : %d article(s) encore en attente de review — report",
            period, pending,
        )
        return

    logger.info(
        "Newsletter recommandations %s : 0 PENDING — déclenchement de l'envoi", period
    )
    total_sent = _send_newsletters_by_source_type(
        source_types=RECOMMENDATION_SOURCE_TYPES,
        days=7,  # fenêtre = semaine uniquement
    )
    _record_newsletter_sent("recommandation", period, articles_sent=total_sent)
    logger.info("Newsletter recommandations envoyée : %d articles au total", total_sent)


# ---------------------------------------------------------------------------
# Envoi par spécialité
# ---------------------------------------------------------------------------

def _get_approved_items(
    specialty_slug: str,
    source_types: tuple[str, ...] | None = None,
    days: int = 35,
) -> list[dict[str, Any]]:
    since = date.today() - timedelta(days=days)
    with get_conn() as conn:
        with conn.cursor() as cur:
            if source_types:
                placeholders = ", ".join(["%s"] * len(source_types))
                cur.execute(
                    f"""
                    SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                           i.tri_json, i.lecture_json, i.categorie,
                           c.title_raw, c.official_url, c.official_date::text
                    FROM items i
                    JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND c.official_date >= %s
                      AND i.specialty_slug = %s
                      AND i.source_type IN ({placeholders})
                    ORDER BY i.score_density DESC, c.official_date DESC;
                    """,
                    (since, specialty_slug, *source_types),
                )
            else:
                cur.execute(
                    """
                    SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                           i.tri_json, i.lecture_json, i.categorie,
                           c.title_raw, c.official_url, c.official_date::text
                    FROM items i
                    JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND c.official_date >= %s
                      AND i.specialty_slug = %s
                    ORDER BY i.score_density DESC, c.official_date DESC;
                    """,
                    (since, specialty_slug),
                )
            rows = cur.fetchall()
    return [
        {"item_id": str(r[0]), "audience": r[1], "specialty_slug": r[2],
         "score_density": r[3], "tri_json": r[4], "lecture_json": r[5],
         "categorie": r[6], "title_raw": r[7], "official_url": r[8],
         "official_date": r[9]}
        for r in rows
    ]


def _get_subscribers(specialty_slug: str) -> list[str]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.email_ciphertext
                FROM users u
                WHERE u.specialty_id = %s AND u.email_verified_at IS NOT NULL;
                """,
                (specialty_slug,),
            )
            rows = cur.fetchall()
    emails = []
    for (raw,) in rows:
        try:
            emails.append(decrypt_email(raw))
        except Exception:
            pass
    return emails


def _send_newsletters_by_source_type(
    source_types: tuple[str, ...] | None = None,
    days: int = 35,
) -> int:
    """Envoie la newsletter à tous les abonnés par spécialité. Retourne le nb total d'articles."""
    total_articles = 0
    for slug in SPECIALTY_LABELS.keys():
        try:
            sent_articles = _send_specialty_newsletter(slug, source_types=source_types, days=days)
            total_articles += sent_articles
        except Exception as e:
            logger.error("Newsletter %s : %s", slug, e)
    return total_articles


def _send_specialty_newsletter(
    specialty_slug: str,
    source_types: tuple[str, ...] | None = None,
    days: int = 35,
) -> int:
    items = _get_approved_items(specialty_slug, source_types=source_types, days=days)
    if not items:
        logger.info("Spécialité %s : aucun item approuvé", specialty_slug)
        return 0
    subscribers = _get_subscribers(specialty_slug)
    if not subscribers:
        logger.info("Spécialité %s : aucun abonné", specialty_slug)
        return 0
    logger.info(
        "Spécialité %s : %d articles → %d abonnés",
        specialty_slug, len(items), len(subscribers),
    )
    subject, html, plain = build_newsletter(
        specialty_slug=specialty_slug, items=items, emission_date=date.today()
    )
    result = send_bulk(subscribers, subject, html, plain)
    logger.info(
        "Spécialité %s : envoyé=%d erreurs=%d",
        specialty_slug, result["sent"], result["failed"],
    )
    return len(items)


# ---------------------------------------------------------------------------
# JOB 3 — Nettoyage des tokens expirés
# ---------------------------------------------------------------------------

def job_cleanup_tokens() -> None:
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

    _scheduler = AsyncIOScheduler(timezone="UTC")

    # ── Collecte réglementation : 1er du mois à 06h UTC ──────────
    regulation_collect_day  = int(os.environ.get("REGULATION_COLLECT_DAY", "1"))
    regulation_collect_hour = int(os.environ.get("REGULATION_COLLECT_HOUR", "6"))

    _scheduler.add_job(
        job_collect_regulation,
        trigger=CronTrigger(day=regulation_collect_day, hour=regulation_collect_hour, minute=0),
        id="regulation_collect",
        name=f"Collecte réglementation (j={regulation_collect_day} h={regulation_collect_hour}h UTC)",
        executor="threadpool",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # ── Collecte recommandations : chaque lundi à 06h UTC ────────
    recommendation_collect_hour = int(os.environ.get("RECOMMENDATION_COLLECT_HOUR", "6"))

    _scheduler.add_job(
        job_collect_recommendations,
        trigger=CronTrigger(day_of_week="mon", hour=recommendation_collect_hour, minute=0),
        id="recommendation_collect",
        name=f"Collecte recommandations (lundi h={recommendation_collect_hour}h UTC)",
        executor="threadpool",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # ── Auto-envoi réglementation : quotidien à 09h UTC ──────────
    # Déclenche dès que 0 PENDING et pas encore envoyée ce mois-ci.
    send_check_hour = int(os.environ.get("NEWSLETTER_CHECK_HOUR", "9"))

    _scheduler.add_job(
        job_try_send_regulation,
        trigger=CronTrigger(hour=send_check_hour, minute=0),
        id="regulation_send_check",
        name=f"Auto-envoi newsletter réglementation (quotidien h={send_check_hour}h UTC)",
        executor="threadpool",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # ── Auto-envoi recommandations : quotidien à 09h30 UTC ───────
    _scheduler.add_job(
        job_try_send_recommendations,
        trigger=CronTrigger(hour=send_check_hour, minute=30),
        id="recommendation_send_check",
        name=f"Auto-envoi newsletter recommandations (quotidien h={send_check_hour}h30 UTC)",
        executor="threadpool",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # ── Nettoyage tokens : quotidien à 03h UTC ───────────────────
    _scheduler.add_job(
        job_cleanup_tokens,
        trigger=CronTrigger(hour=3, minute=0),
        id="daily_cleanup",
        name="Nettoyage tokens expirés (03h00 UTC)",
        executor="threadpool",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    _scheduler.start()
    logger.info(
        "Scheduler démarré — réglementation j=%d h=%dh | recommandations lundi h=%dh | "
        "auto-send check h=%dh (UTC)",
        regulation_collect_day, regulation_collect_hour,
        recommendation_collect_hour, send_check_hour,
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
