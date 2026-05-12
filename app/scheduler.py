# app/scheduler.py
"""
Pipeline — collecte pilotée par la ROUTINE (onglet admin), envoi automatique.

  COLLECTE (déclenchée manuellement via l'onglet Routine, toutes les ~48h)
  ─────────────────────────────────────────────────────────────────────────
  Les fonctions de collecte sont appelées explicitement depuis la routine,
  spécialité par spécialité :
    job_collect_regulation()    → JORF, KALI, LEGI, CIRCULAIRES, ANSM, BO Social
    job_collect_recommendations() → HAS, sociétés savantes, web scraping EU
    job_collect_innovation()    → PubMed (JACC, EHJ, JTCVS, EJCTS…) + RSS presse
  Aucun cron de collecte — la cadence est contrôlée par l'opérateur.

  AUTO-ENVOI NEWSLETTERS (hebdomadaire — vérifie conditions avant d'envoyer)
  ─────────────────────────────────────────────────────────────────────────
  Lundi 09h UTC   → job_try_send_regulation()
      Si 0 PENDING réglementaire ET newsletter pas encore envoyée cette semaine → envoi
  Lundi 09h30 UTC → job_try_send_recommendations()
      Si 0 PENDING recommandation ET pas encore envoyée cette semaine → envoi
  (jour configurable via NEWSLETTER_SEND_DAY_OF_WEEK, défaut "mon")

  MAINTENANCE
  ─────────────────────────────────────────────────────────────────────────
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


def _claim_newsletter_slot(newsletter_type: str, period_label: str) -> bool:
    """Atomically claim a newsletter send slot (prevents double sends).

    Inserts a row with articles_sent=0.  If the row already exists (UNIQUE
    constraint), the INSERT is a no-op and rowcount == 0 → returns False.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO newsletter_sends (newsletter_type, period_label, articles_sent)
                VALUES (%s, %s, 0)
                ON CONFLICT (newsletter_type, period_label) DO NOTHING;
                """,
                (newsletter_type, period_label),
            )
            return cur.rowcount == 1


def _finalize_newsletter_sent(newsletter_type: str, period_label: str, articles_sent: int) -> None:
    """Update articles_sent after a successful send."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE newsletter_sends SET sent_at = now(), articles_sent = %s
                WHERE newsletter_type = %s AND period_label = %s;
                """,
                (articles_sent, newsletter_type, period_label),
            )


def _release_newsletter_slot(newsletter_type: str, period_label: str) -> None:
    """Release a claimed slot when no articles were sent (allows retry next day)."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM newsletter_sends
                WHERE newsletter_type = %s AND period_label = %s AND articles_sent = 0;
                """,
                (newsletter_type, period_label),
            )


def _weekly_period() -> str:
    """Label de la semaine ISO courante, ex. '2026-W16'.
    Utilisé pour toutes les newsletters (réglementation + recommandations)
    depuis le passage en cadence hebdomadaire.
    """
    today = date.today()
    iso = today.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


# Alias pour compatibilité avec les appels existants
_regulation_period    = _weekly_period
_recommendation_period = _weekly_period


# ---------------------------------------------------------------------------
# JOB 1a — Collecte réglementation (1er du mois)
# ---------------------------------------------------------------------------

def job_collect_regulation(days: int = 120) -> None:
    logger.info("=" * 60)
    logger.info("JOB COLLECTE RÉGLEMENTATION démarré — %s (fenêtre %d j)", date.today().isoformat(), days)
    logger.info("=" * 60)

    report: dict[str, Any] = {}

    # ── 1. JORF ──────────────────────────────────────────────────
    try:
        from app.piste_routes import (
            _piste_call, _extract_list, _keep_item_with_reason,
            _parse_date10, _official_url, _sha256_hex, _json_canonical_bytes,
        )
        from app.collector_utils import build_candidate_row, insert_candidate
        from app.llm_analysis import pre_filter_candidate as _pfc_jorf

        source = "legifrance_jorf"
        today = date.today()
        start = today - timedelta(days=days)
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
                        # Pré-filtre heuristique (nominations, événements…)
                        keep, _ = _pfc_jorf((title or "").strip(), source=source)
                        if not keep:
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

    # ── 1.5. JORF remboursement — convention médicale, CCAM, nomenclature ────
    # Filtre titre sur REMBOURSEMENT_KEYWORDS → source = legifrance_jorf_remboursement
    try:
        from app.piste_routes import (
            _piste_call as _pc_rm, _extract_list as _el_rm, _keep_item_with_reason as _kir_rm,
            _parse_date10 as _pd_rm, _official_url as _ou_rm, _sha256_hex as _sh_rm,
            _json_canonical_bytes as _jcb_rm, _build_titre_champs, REMBOURSEMENT_KEYWORDS,
        )
        from app.collector_utils import build_candidate_row as _bcr_rm, insert_candidate as _ic_rm

        source_rm = "legifrance_jorf_remboursement"
        today_rm = date.today()
        start_rm = today_rm - timedelta(days=days)
        pg_size_rm, max_pg_rm = 50, 40
        seen_rm = ins_rm = dup_rm = 0

        with get_conn() as conn:
            with conn.cursor() as cur:
                for pg_rm in range(1, max_pg_rm + 1):
                    payload_rm = {
                        "fond": "JORF",
                        "recherche": {
                            "pageNumber": pg_rm,
                            "pageSize": pg_size_rm,
                            "operateur": "ET",
                            "typePagination": "DEFAUT",
                            "champs": _build_titre_champs(REMBOURSEMENT_KEYWORDS),
                            "filtres": [{
                                "facette": "DATE_PUBLICATION",
                                "dates": {
                                    "start": start_rm.strftime("%Y-%m-%dT00:00:00.000+0000"),
                                    "end": today_rm.strftime("%Y-%m-%dT23:59:59.000+0000"),
                                },
                            }],
                        },
                    }
                    try:
                        data_rm = _pc_rm("/search", payload_rm)
                    except Exception:
                        break
                    items_rm = _el_rm(data_rm)
                    if not items_rm:
                        break
                    for it_rm in items_rm:
                        if not isinstance(it_rm, dict):
                            continue
                        seen_rm += 1
                        titles_rm = it_rm.get("titles") if isinstance(it_rm.get("titles"), list) else []
                        t0_rm = titles_rm[0] if titles_rm and isinstance(titles_rm[0], dict) else {}
                        jorftext_id_rm = t0_rm.get("cid")
                        title_rm = t0_rm.get("title")
                        nature_rm = it_rm.get("nature") or it_rm.get("type")
                        ok_rm, _ = _kir_rm(nature_rm, title_rm)
                        if not ok_rm:
                            continue
                        pub_s_rm = _pd_rm(it_rm.get("datePublication")) or _pd_rm(it_rm.get("date"))
                        if not pub_s_rm:
                            continue
                        pub_d_rm = date.fromisoformat(pub_s_rm)
                        if not (start_rm <= pub_d_rm <= today_rm):
                            continue
                        if not (isinstance(jorftext_id_rm, str) and jorftext_id_rm.startswith("JORFTEXT")):
                            continue
                        row_rm = _bcr_rm(
                            source=source_rm, external_id=jorftext_id_rm,
                            official_url=_ou_rm(jorftext_id_rm),
                            official_date=pub_d_rm,
                            title_raw=(title_rm or "").strip() or "(no title)",
                            jorftext_id=jorftext_id_rm, raw_payload=it_rm,
                        )
                        if _ic_rm(cur, row_rm):
                            ins_rm += 1
                        else:
                            dup_rm += 1
                conn.commit()

        report["jorf_remboursement"] = {"seen": seen_rm, "inserted": ins_rm, "deduped": dup_rm}
        logger.info("JORF remboursement : vu=%d ins=%d dup=%d", seen_rm, ins_rm, dup_rm)
    except Exception as e:
        logger.error("JORF remboursement échoué : %s", e)
        report["jorf_remboursement"] = {"error": str(e)}

    # ── 2. KALI / CIRCULAIRES ─────────────────────────────────────
    # LEGI retiré : le fond LEGI ne supporte pas le endpoint /search (400 systématique).
    # KALI  : pas de filtre champs côté PISTE (typeRecherche EXACTE non supporté sur KALI).
    #         Filtre santé appliqué en Python sur le titre après récupération.
    # CIRC  : pas de filtre DATE_PUBLICATION côté PISTE (500 serveur). Filtrage date en Python
    #         sur titles[0].startDate retourné par l'API.
    try:
        from app.piste_routes import _piste_call as pc, _extract_list as el, _parse_date10 as pd10, _sha256_hex as sh, _json_canonical_bytes as jcb
        from app.db import get_conn as _get_conn
        from app.llm_analysis import pre_filter_candidate as _pfc
        import json as _json
        import re as _re

        FONDS_CONFIG = {
            "KALI": "piste_kali",
            "CIRC": "piste_circ",
        }
        # KALI : filtre Python sur titre — conventions collectives du secteur santé uniquement
        _KALI_RE = _re.compile(
            r"(?i)\b(m[eé]decin|pharmacien|infirmier|sage.femme|auxiliaire.m[eé]dical|"
            r"cabinet.m[eé]dical|clinique|chirurgien|dentiste|kin[eé]sith[eé]rapeute|"
            r"orthophoniste|professionnel.de.sant[eé])\b"
        )

        insert_sql = """
        INSERT INTO candidates (source, official_url, official_date, title_raw, content_raw, raw_json, raw_sha256, dedupe_key, status)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, 'NEW') ON CONFLICT (dedupe_key) DO NOTHING;
        """
        extra_report: dict[str, Any] = {}

        for fond, src in FONDS_CONFIG.items():
            try:
                today_d = date.today()
                start_d = today_d - timedelta(days=days)
                ins = dup = s = filtered = 0

                with _get_conn() as conn:
                    with conn.cursor() as cur:
                        for pg in range(1, 21):
                            # KALI : filtre DATE_PUBLICATION côté PISTE (supporté)
                            # CIRC : pas de filtre date côté PISTE, on filtre en Python
                            recherche: dict = {
                                "pageNumber": pg, "pageSize": 50,
                                "operateur": "ET", "typePagination": "DEFAUT",
                            }
                            if fond == "KALI":
                                recherche["filtres"] = [{"facette": "DATE_PUBLICATION", "dates": {
                                    "start": start_d.strftime("%Y-%m-%dT00:00:00.000+0000"),
                                    "end": today_d.strftime("%Y-%m-%dT23:59:59.000+0000"),
                                }}]
                            data = pc("/search", {"fond": fond, "recherche": recherche})
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
                                title = (t0.get("title") or "(no title)").strip()
                                # Date : datePublication pour KALI, startDate dans t0 pour CIRC
                                pub_s = (pd10(it.get("datePublication")) or pd10(it.get("date"))
                                         or pd10(t0.get("startDate")))
                                if not pub_s:
                                    continue
                                pub_d_val = date.fromisoformat(pub_s)
                                if not (start_d <= pub_d_val <= today_d):
                                    continue
                                # KALI : filtre Python secteur santé
                                if fond == "KALI" and not _KALI_RE.search(title):
                                    filtered += 1
                                    continue
                                # Pré-filtre heuristique (nominations, événements…)
                                keep, _reason = _pfc(title, source=src)
                                if not keep:
                                    filtered += 1
                                    continue
                                dk = sh(f"{src}|{text_id}".encode())
                                rs = sh(jcb(it))
                                cur.execute(insert_sql, (
                                    src,
                                    f"https://www.legifrance.gouv.fr/{fond.lower()}/id/{text_id}",
                                    pub_d_val, title, None,
                                    _json.dumps(it, ensure_ascii=False), rs, dk,
                                ))
                                if cur.rowcount == 1:
                                    ins += 1
                                else:
                                    dup += 1
                    conn.commit()
                extra_report[fond] = {"seen": s, "inserted": ins, "deduped": dup, "filtered": filtered}
                logger.info("%s : vu=%d ins=%d dup=%d filtrés=%d", fond, s, ins, dup, filtered)
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

        report["ansm"] = collect_ansm(days=days)

        # BO Social et CNOM depuis FEEDS, filtrés sur source_type = reglementaire
        reg_sources = {s for s, t in SOURCE_TO_TYPE.items() if t == "reglementaire"}
        for feed in FEEDS:
            if feed["source"] in reg_sources and not feed["source"].startswith("ansm") and not feed.get("disabled"):
                try:
                    r = collect_feed(feed, days=days)
                    report[feed["source"]] = r
                    logger.info("[%s] ins=%d", feed["source"], r.get("inserted", 0))
                except Exception as e3:
                    logger.error("[%s] erreur : %s", feed["source"], e3)
    except Exception as e:
        logger.error("RSS réglementation échoué : %s", e)
        report["rss_regulation"] = {"error": str(e)}

    # ── 4. CNOM — scraper (RSS vide depuis 2026) ─────────────────
    try:
        from app.web_scraper import collect_cnom
        report["cnom_scraper"] = collect_cnom(days=days)
        logger.info("CNOM scraper : ins=%d", report["cnom_scraper"].get("inserted", 0))
    except Exception as e:
        logger.error("CNOM scraper échoué : %s", e)
        report["cnom_scraper"] = {"error": str(e)}

    # ── 5. ameli.fr/medecin — actualités CNAM (pas de RSS) ───────
    try:
        from app.web_scraper import collect_ameli_medecin
        report["ameli_medecin"] = collect_ameli_medecin(days=days)
        logger.info("ameli.fr médecin : ins=%d", report["ameli_medecin"].get("inserted", 0))
    except Exception as e:
        logger.error("ameli.fr médecin échoué : %s", e)
        report["ameli_medecin"] = {"error": str(e)}

    # ── 6. CARMF — retraite et cotisations médecins libéraux ─────
    try:
        from app.web_scraper import collect_carmf
        report["carmf"] = collect_carmf(days=days)
        logger.info("CARMF : ins=%d", report["carmf"].get("inserted", 0))
    except Exception as e:
        logger.error("CARMF échoué : %s", e)
        report["carmf"] = {"error": str(e)}

    # ── 7. CARPIMKO — retraite auxiliaires médicaux libéraux ─────
    try:
        from app.web_scraper import collect_carpimko
        report["carpimko"] = collect_carpimko(days=days)
        logger.info("CARPIMKO : ins=%d", report["carpimko"].get("inserted", 0))
    except Exception as e:
        logger.error("CARPIMKO échoué : %s", e)
        report["carpimko"] = {"error": str(e)}

    # ── 8. Analyse LLM ───────────────────────────────────────────
    # DÉSACTIVÉ : le triage se fait manuellement dans la conversation Claude Pro.
    # _run_llm_batch()

    logger.info("JOB COLLECTE RÉGLEMENTATION terminé")
    return report


# ---------------------------------------------------------------------------
# JOB 1b — Collecte recommandations (chaque lundi)
# ---------------------------------------------------------------------------

def job_collect_recommendations(specialty_slug: str | None = None, skip_global_hint: bool = False) -> None:
    logger.info("=" * 60)
    logger.info("JOB COLLECTE RECOMMANDATIONS démarré — %s", date.today().isoformat())
    logger.info("=" * 60)

    report: dict[str, Any] = {}

    # ── HAS + sociétés savantes (RSS) ────────────────────────────
    # En mode spécialité : collect_pratique filtrée par specialty_hint.
    # En mode global : collect_pratique + collect_has sans filtre.
    # skip_global_hint=True : sources hint="tous" ignorées (déjà collectées)
    try:
        from app.rss_collector import collect_pratique
        report["pratique"] = collect_pratique(days=120, specialty_slug=specialty_slug, skip_global_hint=skip_global_hint)
        logger.info("Recommandations RSS collectées (specialty=%s)", specialty_slug)
    except Exception as e:
        logger.error("RSS recommandations échoué : %s", e)
        report["pratique"] = {"error": str(e)}

    if specialty_slug is None:
        try:
            from app.rss_collector import collect_has
            report["has"] = collect_has(days=120)
        except Exception as e:
            logger.error("collect_has échoué : %s", e)
            report["has"] = {"error": str(e)}

        # ── HAS CT (avis médicaments — source_type déterminé par LLM) ────
        try:
            from app.rss_collector import collect_feed, FEEDS
            for feed in FEEDS:
                if feed["source"] == "has_ct":
                    r = collect_feed(feed, days=120)
                    report["has_ct"] = r
                    logger.info("[has_ct] ins=%d", r.get("inserted", 0))
        except Exception as e:
            logger.error("has_ct échoué : %s", e)

    # ── Web scraping européen (ESC, EULAR, EAU, ESCMID…) ────────
    # Guidelines publiées 2-10/an par société → collecte hebdo suffit.
    try:
        from app.web_scraper import scrape_all_web
        web_report = scrape_all_web(specialty_slug=specialty_slug)
        report["web_scraping"] = web_report
        total_web_ins = sum(v.get("inserted", 0) for v in web_report.values() if isinstance(v, dict))
        logger.info("Web scraping (FR + EU) : %d sources, %d insérés", len(web_report), total_web_ins)
    except Exception as e:
        logger.error("Web scraping échoué : %s", e)
        report["web_scraping"] = {"error": str(e)}

    # ── Analyse LLM ──────────────────────────────────────────────
    # DÉSACTIVÉ : le triage se fait manuellement dans la conversation Claude Pro.
    # _run_llm_batch()

    logger.info("JOB COLLECTE RECOMMANDATIONS terminé")
    return report


# ---------------------------------------------------------------------------
# Collecte innovation (hebdomadaire — mercredi par défaut)
# ---------------------------------------------------------------------------

def job_collect_innovation() -> None:
    """
    Collecte toutes les sources innovation (RSS + PubMed + API).
    Fenêtre : 10 jours. Analyse LLM à la fin.
    """
    logger.info("=" * 60)
    logger.info("JOB COLLECTE INNOVATION démarré — %s", date.today().isoformat())
    logger.info("=" * 60)
    from app.collector import collect_all
    report = collect_all(days=120)
    # DÉSACTIVÉ : le triage se fait manuellement dans la conversation Claude Pro.
    # _run_llm_batch()
    logger.info("JOB COLLECTE INNOVATION terminé")
    return report


# ---------------------------------------------------------------------------
# Collecte par spécialité (cœur de la Routine)
# ---------------------------------------------------------------------------

def collect_by_specialty(
    specialty_slug: str,
    days: int = 120,
    skip_global: bool = False,
) -> dict[str, Any]:
    """
    Collecte COMPLÈTE pour une spécialité — un seul déclencheur, tout inclus :

      1. Innovation filtrée par spécialité (RSS + PubMed + API via collector.py)
      2. Réglementation globale (JORF, KALI, LEGI, ANSM, BO Social)
      3. Recommandations globales (HAS, sociétés savantes, web scraping EU)
      4. Analyse LLM (prompt spé-spécifique via SOURCE_SPECIALTY_HINTS)

    La déduplication DB garantit l'idempotence si plusieurs spés tournent le même jour.

    Si skip_global=True (GitHub Actions après collect_global.py), la réglementation
    globale et les sources hint="tous" sont ignorées — déjà collectées.
    """
    logger.info("=" * 60)
    logger.info("COLLECTE [%s] démarrée — %s", specialty_slug, date.today().isoformat())
    logger.info("=" * 60)

    from app.collector import collect_by_specialty_sources
    report = collect_by_specialty_sources(specialty_slug, days=days, skip_global=skip_global)

    if not skip_global:
        try:
            report["regulation"] = job_collect_regulation()
        except Exception as e:
            logger.error("[%s] Réglementation échouée : %s", specialty_slug, e)
            report["regulation"] = {"error": str(e)}

    try:
        report["recommendations"] = job_collect_recommendations(
            specialty_slug=specialty_slug,
            skip_global_hint=skip_global,
        )
    except Exception as e:
        logger.error("[%s] Recommandations échouées : %s", specialty_slug, e)
        report["recommendations"] = {"error": str(e)}

    # DÉSACTIVÉ : le triage se fait manuellement dans la conversation Claude Pro.
    # _run_llm_batch()

    logger.info("COLLECTE [%s] terminée", specialty_slug)
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
    Vérifie chaque vendredi si la newsletter réglementation peut être envoyée :
    - Aucun item PENDING de type réglementaire/thérapeutique
    - Newsletter pas encore envoyée cette semaine (période ISO)
    Si oui : envoie (fenêtre = 10 derniers jours) et enregistre.
    """
    period = _regulation_period()

    # Fast-path : déjà envoyée ?
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

    # Atomic claim — prevents double sends if two threads reach this point
    if not _claim_newsletter_slot("reglementaire", period):
        logger.info("Newsletter réglementation %s déjà claim par un autre worker — skip", period)
        return

    logger.info(
        "Newsletter réglementation %s : 0 PENDING — déclenchement de l'envoi", period
    )
    total_sent = _send_newsletters_by_source_type(
        source_types=REGULATION_SOURCE_TYPES,
        days=120,
    )
    if total_sent > 0:
        _finalize_newsletter_sent("reglementaire", period, articles_sent=total_sent)
        logger.info("Newsletter réglementation envoyée : %d articles au total", total_sent)
    else:
        # Release slot so it can be retried tomorrow
        _release_newsletter_slot("reglementaire", period)
        logger.warning(
            "[newsletter réglementation] 0 items approuvés pour la période %s — "
            "slot libéré, nouvelle tentative possible demain",
            period,
        )


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

    # Atomic claim — prevents double sends
    if not _claim_newsletter_slot("recommandation", period):
        logger.info("Newsletter recommandations %s déjà claim par un autre worker — skip", period)
        return

    logger.info(
        "Newsletter recommandations %s : 0 PENDING — déclenchement de l'envoi", period
    )
    total_sent = _send_newsletters_by_source_type(
        source_types=RECOMMENDATION_SOURCE_TYPES,
        days=120,
    )
    if total_sent > 0:
        _finalize_newsletter_sent("recommandation", period, articles_sent=total_sent)
        logger.info("Newsletter recommandations envoyée : %d articles au total", total_sent)
    else:
        _release_newsletter_slot("recommandation", period)
        logger.warning(
            "[newsletter recommandations] 0 items approuvés pour la période %s — "
            "slot libéré, nouvelle tentative possible demain",
            period,
        )


# ---------------------------------------------------------------------------
# Envoi par spécialité
# ---------------------------------------------------------------------------

def _get_approved_items(
    specialty_slug: str,
    source_types: tuple[str, ...] | None = None,
    days: int = 120,
    include_transversal: bool = False,
) -> list[dict[str, Any]]:
    since = date.today() - timedelta(days=days)
    # Clause optionnelle pour inclure les articles TRANSVERSAL_LIBERAL
    transversal_clause = "OR i.audience = 'TRANSVERSAL_LIBERAL'" if include_transversal else ""
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
                      AND (i.specialty_slug = %s {transversal_clause})
                      AND i.source_type IN ({placeholders})
                      AND c.source NOT IN ('ansm_ruptures_med', 'ansm_ruptures_vaccins')
                    ORDER BY i.score_density DESC, c.official_date DESC;
                    """,
                    (since, specialty_slug, *source_types),
                )
            else:
                cur.execute(
                    f"""
                    SELECT i.id, i.audience, i.specialty_slug, i.score_density,
                           i.tri_json, i.lecture_json, i.categorie,
                           c.title_raw, c.official_url, c.official_date::text
                    FROM items i
                    JOIN candidates c ON c.id = i.candidate_id
                    WHERE i.review_status = 'APPROVED'
                      AND c.official_date >= %s
                      AND (i.specialty_slug = %s {transversal_clause})
                      AND c.source NOT IN ('ansm_ruptures_med', 'ansm_ruptures_vaccins')
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
                WHERE u.specialty_id = %s
                  AND u.email_verified_at IS NOT NULL
                  AND u.is_unsubscribed = false
                  AND (u.bounce_status IS NULL OR u.bounce_status != 'permanent');
                """,
                (specialty_slug,),
            )
            rows = cur.fetchall()
    emails = []
    for (raw,) in rows:
        try:
            emails.append(decrypt_email(raw))
        except Exception as e:
            logger.warning("Décryptage email échoué (specialty=%s) : %s", specialty_slug, e)
    return emails


def _send_newsletters_by_source_type(
    source_types: tuple[str, ...] | None = None,
    days: int = 120,
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
    days: int = 120,
) -> int:
    items = _get_approved_items(specialty_slug, source_types=source_types, days=days, include_transversal=True)
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
# JOB 2c — Newsletter unifiée tous les 2 jours (régle + reco + innov)
# ---------------------------------------------------------------------------

def job_send_unified() -> None:
    """
    Envoie une newsletter unifiée (tous types) par spécialité.

    - Fenêtre : 3 derniers jours (léger buffer vs cadence 2j)
    - Pas de blocage sur PENDING — envoie les APPROVED directement
    - Inclut les articles TRANSVERSAL_LIBERAL pour toutes les spécialités
    - Déclenchement : GitHub Actions cron '0 18 */2 * *'
    - Déduplication : period_label = date du jour (1 envoi max par jour)
    """
    period = date.today().isoformat()
    newsletter_type = "unified"

    if _newsletter_already_sent(newsletter_type, period):
        logger.info("Newsletter unifiée %s déjà envoyée — skip", period)
        return

    if not _claim_newsletter_slot(newsletter_type, period):
        logger.info("Newsletter unifiée %s déjà claim — skip", period)
        return

    logger.info("Newsletter unifiée %s — déclenchement", period)

    total_sent = 0
    for slug in SPECIALTY_LABELS.keys():
        try:
            items = _get_approved_items(
                slug,
                source_types=None,   # tous types : régle + reco + innov
                days=3,
                include_transversal=True,
            )
            if not items:
                logger.info("[unified] %s : aucun article approuvé sur 3j", slug)
                continue
            subscribers = _get_subscribers(slug)
            if not subscribers:
                logger.info("[unified] %s : aucun abonné", slug)
                continue
            logger.info("[unified] %s : %d articles → %d abonnés", slug, len(items), len(subscribers))
            subject, html, plain = build_newsletter(
                specialty_slug=slug, items=items, emission_date=date.today()
            )
            if subject is None:
                logger.info("[unified] %s : newsletter vide après filtrage — skip", slug)
                continue
            result = send_bulk(subscribers, subject, html, plain)
            logger.info("[unified] %s : envoyé=%d erreurs=%d", slug, result["sent"], result["failed"])
            total_sent += len(items)
        except Exception as e:
            logger.error("[unified] %s : %s", slug, e)

    if total_sent > 0:
        _finalize_newsletter_sent(newsletter_type, period, total_sent)
        logger.info("Newsletter unifiée %s terminée — %d articles au total", period, total_sent)
    else:
        _release_newsletter_slot(newsletter_type, period)
        logger.warning("Newsletter unifiée %s — 0 articles envoyés, slot libéré", period)


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

    # NOTE : les jobs de COLLECTE (regulation, recommendations, innovation)
    # ne sont plus enregistrés ici — ils sont appelés depuis l'onglet Routine
    # (toutes les ~48h, spécialité par spécialité, à la main de l'opérateur).
    # Les fonctions job_collect_*() restent disponibles comme callables.

    # ── Auto-envoi newsletters : hebdomadaire (lundi par défaut) ─
    # Jour configurable via NEWSLETTER_SEND_DAY_OF_WEEK (ex. "mon", "fri").
    # Vérifie les conditions (0 PENDING + pas encore envoyée cette semaine) avant d'agir.
    send_check_hour = int(os.environ.get("NEWSLETTER_CHECK_HOUR", "9"))
    send_dow = os.environ.get("NEWSLETTER_SEND_DAY_OF_WEEK", "mon")

    _scheduler.add_job(
        job_try_send_regulation,
        trigger=CronTrigger(day_of_week=send_dow, hour=send_check_hour, minute=0),
        id="regulation_send_check",
        name=f"Auto-envoi newsletter réglementation (hebdo {send_dow} {send_check_hour}h UTC)",
        executor="threadpool",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # ── Auto-envoi recommandations : même jour, 30 min après ──────
    _scheduler.add_job(
        job_try_send_recommendations,
        trigger=CronTrigger(day_of_week=send_dow, hour=send_check_hour, minute=30),
        id="recommendation_send_check",
        name=f"Auto-envoi newsletter recommandations (hebdo {send_dow} {send_check_hour}h30 UTC)",
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
        "Scheduler démarré — auto-envoi hebdo (%s %dh / %dh30 UTC) | cleanup tokens 03h UTC",
        send_dow, send_check_hour, send_check_hour,
    )
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler arrêté")


def _startup_catchup() -> None:
    """Rattrapage au démarrage : si le service Render a dormi et raté un job
    APScheduler, on détecte l'absence de candidats pour la période en cours
    et on lance la collecte immédiatement."""
    today = date.today()
    month_start = today.replace(day=1)

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Vérifier si des candidats existent pour le mois en cours
            cur.execute(
                "SELECT COUNT(*) FROM candidates WHERE created_at >= %s;",
                (month_start,),
            )
            month_candidates = cur.fetchone()[0]

    if month_candidates == 0:
        logger.warning(
            "RATTRAPAGE : 0 candidats collectés depuis %s — "
            "lancement immédiat de la collecte réglementation + recommandations",
            month_start.isoformat(),
        )
        try:
            job_collect_regulation()
        except Exception as e:
            logger.error("Rattrapage collecte réglementation échoué : %s", e)
        try:
            job_collect_recommendations()
        except Exception as e:
            logger.error("Rattrapage collecte recommandations échoué : %s", e)
    else:
        logger.info(
            "Rattrapage : %d candidats déjà collectés ce mois-ci — rien à faire",
            month_candidates,
        )


@asynccontextmanager
async def lifespan(app: Any):
    # Auto-apply pending SQL migrations on startup
    try:
        from app.migrations import run_migrations
        n, files = run_migrations()
        if n:
            logger.info("Auto-migration : %d appliquée(s) — %s", n, ", ".join(files))
        else:
            logger.info("Auto-migration : aucune migration en attente")
    except Exception as e:
        logger.error("Auto-migration échouée : %s", e)

    enabled = os.environ.get("SCHEDULER_ENABLED", "false").lower() == "true"
    if enabled:
        start_scheduler()
        # Rattrapage des collectes manquées (Render free tier dort et rate les crons)
        # Lancé dans un thread pour ne PAS bloquer le lifespan (yield doit arriver vite
        # sinon FastAPI ne sert aucune requête).
        import threading
        threading.Thread(target=_startup_catchup, daemon=True, name="startup-catchup").start()
    else:
        logger.info("Scheduler désactivé (SCHEDULER_ENABLED=false)")
    yield
    stop_scheduler()
