#!/usr/bin/env python3
"""
Script de collecte par spécialité — appelé par GitHub Actions.

Usage : python3 scripts/collect_specialty.py <slug> [days]

Env vars requises (passées via GitHub Secrets) :
  DATABASE_URL, PISTE_CLIENT_ID, PISTE_CLIENT_SECRET
"""
import sys
import os
import json
import logging

# Logging lisible dans GitHub Actions
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("collect_specialty")

if len(sys.argv) < 2:
    print("Usage: python3 scripts/collect_specialty.py <slug> [days]", file=sys.stderr)
    sys.exit(1)

slug = sys.argv[1]
days = int(sys.argv[2]) if len(sys.argv) > 2 else 120

# Vérifier les vars d'env obligatoires
required = ["DATABASE_URL", "PISTE_CLIENT_ID", "PISTE_CLIENT_SECRET"]
missing = [v for v in required if not os.environ.get(v)]
if missing:
    print(f"ERREUR — Variables manquantes : {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

# SCHEDULER_ENABLED=false pour éviter de lancer APScheduler
os.environ.setdefault("SCHEDULER_ENABLED", "false")

skip_global = os.environ.get("MEDNEWS_SKIP_GLOBAL", "false").lower() == "true"

logger.info("=== Collecte [%s] — fenêtre %d jours | skip_global=%s ===", slug, days, skip_global)

try:
    from app.scheduler import collect_by_specialty
    report = collect_by_specialty(slug, days=days, skip_global=skip_global)

    # Résumé lisible
    logger.info("--- Rapport [%s] ---", slug)

    rss = report.get("rss", {})
    rss_inserted = sum(v.get("inserted", 0) for v in rss.values() if isinstance(v, dict))
    rss_errors = [k for k, v in rss.items() if isinstance(v, dict) and v.get("error")]
    logger.info("RSS     : %d sources | %d insérés | %d erreurs", len(rss), rss_inserted, len(rss_errors))
    if rss_errors:
        logger.warning("RSS erreurs : %s", rss_errors[:5])

    pubmed = report.get("pubmed", {})
    pub_inserted = sum(v.get("inserted", 0) for v in pubmed.values() if isinstance(v, dict))
    pub_errors = [k for k, v in pubmed.items() if isinstance(v, dict) and v.get("error")]
    logger.info("PubMed  : %d sources | %d insérés | %d erreurs", len(pubmed), pub_inserted, len(pub_errors))
    if pub_errors:
        logger.warning("PubMed erreurs : %s", pub_errors[:5])

    reg = report.get("regulation", {})
    if isinstance(reg, dict) and "error" not in reg:
        reg_inserted = sum(v.get("inserted", 0) for v in reg.values() if isinstance(v, dict))
        logger.info("Réglementation : %d insérés", reg_inserted)
    else:
        logger.warning("Réglementation : %s", reg.get("error") if isinstance(reg, dict) else reg)

    reco = report.get("recommendations", {})
    if isinstance(reco, dict) and "error" not in reco:
        reco_inserted = sum(v.get("inserted", 0) for v in reco.values() if isinstance(v, dict) if isinstance(v, dict))
        logger.info("Recommandations : %d insérés", reco_inserted)
    else:
        logger.warning("Recommandations : %s", reco.get("error") if isinstance(reco, dict) else reco)

    total = rss_inserted + pub_inserted
    logger.info("TOTAL [%s] : %d candidats insérés", slug, total)

except Exception as e:
    logger.exception("ERREUR FATALE pour [%s] : %s", slug, e)
    sys.exit(1)
