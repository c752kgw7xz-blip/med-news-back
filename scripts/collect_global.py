#!/usr/bin/env python3
"""
Collecte des sources globales (cross-spécialités) — à lancer UNE FOIS avant les runs par spé.

Couvre :
  1. Réglementation (ANSM, CNOM, ameli.fr, CARMF, CSMF, BO Social, JORF via PISTE...)
  2. Recommandations cross-spé (HAS rbp/ct/dm/acces_precoces, sociétés savantes globales,
     web scraping EU sans filtre de spécialité)
  3. RSS innovation cross-spé (NEJM, Lancet, JAMA, EMA, nature_medicine, healio_hemato_onco...)
  4. API cross-spé (FDA 510k, FDA PMA, EUDAMED)

Usage : python3 scripts/collect_global.py [days]

Env vars requises :
  DATABASE_URL, PISTE_CLIENT_ID, PISTE_CLIENT_SECRET
"""
import sys
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("collect_global")

required = ["DATABASE_URL", "PISTE_CLIENT_ID", "PISTE_CLIENT_SECRET"]
missing = [v for v in required if not os.environ.get(v)]
if missing:
    print(f"ERREUR — Variables manquantes : {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

os.environ.setdefault("SCHEDULER_ENABLED", "false")

days = int(sys.argv[1]) if len(sys.argv) > 1 else 120

logger.info("=== Collecte globale — fenêtre %d jours ===", days)

try:
    from app.scheduler import job_collect_regulation, job_collect_recommendations
    from app.sources import ALL_FEEDS, API_SOURCES, FR_REGULATORY_FEEDS
    from app.rss_collector import collect_feed
    from app.collector import _API_DISPATCH

    total = 0

    # ── 1. Réglementation globale ─────────────────────────────────────────
    # ANSM (RSS + scrapers), CNOM scraper, ameli.fr scraper, CARMF scraper,
    # CARPIMKO, CSMF, BO Social, JORF via PISTE, fonds sociaux...
    logger.info("--- [1/4] Réglementation ---")
    try:
        reg = job_collect_regulation()
        reg_ins = sum(v.get("inserted", 0) for v in reg.values() if isinstance(v, dict))
        logger.info("Réglementation : %d insérés", reg_ins)
        total += reg_ins
    except Exception as e:
        logger.error("Réglementation échouée : %s", e)

    # ── 2. Recommandations cross-spé ──────────────────────────────────────
    # HAS (rbp, ct, dm, acces_precoces), collect_pratique sans filtre (toutes
    # sociétés savantes hint="tous"), web scraping EU global (ESC, EULAR, EAU...)
    logger.info("--- [2/4] Recommandations cross-spé ---")
    try:
        reco = job_collect_recommendations(specialty_slug=None)
        reco_ins = sum(v.get("inserted", 0) for v in reco.values() if isinstance(v, dict))
        logger.info("Recommandations : %d insérés", reco_ins)
        total += reco_ins
    except Exception as e:
        logger.error("Recommandations échouées : %s", e)

    # ── 3. RSS innovation cross-spé (hint="tous") ─────────────────────────
    # NEJM, Lancet, JAMA, EMA new medicines/news/guidelines, nature_medicine,
    # eclinmedicine, healio_hemato_onco, medpage_surgery, quotidien_medecin...
    # FR_REGULATORY_FEEDS (HAS rbp/ct/dm, ANSM, BO…) exclus : déjà couverts
    # par job_collect_regulation() [1/4] et collect_pratique() [2/4].
    logger.info("--- [3/4] RSS cross-spé ---")
    _pratique_sources = {f["source"] for f in FR_REGULATORY_FEEDS}
    rss_global = [
        f for f in ALL_FEEDS
        if f.get("specialty_hint") == "tous"
        and not f.get("disabled")
        and f["source"] not in _pratique_sources
    ]
    rss_ins = 0
    rss_errors = []
    for feed in rss_global:
        try:
            r = collect_feed(feed, days=days)
            ins = r.get("inserted", 0)
            rss_ins += ins
            if ins > 0:
                logger.info("[%s] ins=%d", feed["source"], ins)
        except Exception as e:
            logger.error("[%s] erreur : %s", feed["source"], e)
            rss_errors.append(feed["source"])
    logger.info("RSS cross-spé : %d sources | %d insérés | %d erreurs", len(rss_global), rss_ins, len(rss_errors))
    if rss_errors:
        logger.warning("RSS erreurs : %s", rss_errors)
    total += rss_ins

    # ── 4. API cross-spé (FDA 510k, FDA PMA, EUDAMED) ────────────────────
    logger.info("--- [4/4] API cross-spé ---")
    api_global = [s for s in API_SOURCES if s.get("specialty_hint") == "tous"]
    api_ins = 0
    for src in api_global:
        fn = _API_DISPATCH.get(src.get("collector", ""))
        if not fn:
            continue
        try:
            r = fn(days=days)
            ins = r.get("inserted", 0)
            api_ins += ins
            logger.info("[%s] ins=%d", src["source"], ins)
        except Exception as e:
            logger.error("[%s] erreur : %s", src["source"], e)
    logger.info("API cross-spé : %d sources | %d insérés", len(api_global), api_ins)
    total += api_ins

    logger.info("=== TOTAL global : %d candidats insérés ===", total)

except Exception as e:
    logger.exception("ERREUR FATALE : %s", e)
    sys.exit(1)
