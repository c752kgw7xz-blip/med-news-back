# app/fda_collector.py
"""
Collecteur FDA — approbations de dispositifs médicaux vasculaires (open.fda.gov).

Sources :
  device/pma.json  : Approbations PMA Class III (endoprothèses, greffons aortiques,
                     filtres cave — seuls la FDA peut approuver ces implants à haut risque)
  device/510k.json : Clearances 510(k) Class II (cathéters, systèmes de délivrance,
                     stents périphériques, accès vasculaires)

Filtre :
  1. Comité consultatif "CH" (Circulatory System = cardiovasculaire) côté API
  2. Mots-clés vasculaires côté client (élimine pacemakers, valves cardiaques, etc.)

API publique open.fda.gov :
  - Pas de clé requise (rate limit 240 req/min)
  - Avec clé FDA_API_KEY : 120 000 req/jour (env var)

Pourquoi c'est utile :
  Un chirurgien vasculaire rate une approbation FDA si elle n'est pas relayée par
  une publication. Or les journaux publient les studies APRÈS l'approbation.
  Ce collecteur comble le délai : le dispositif est disponible dès l'approbation.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import date, timedelta
from typing import Any

import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn

logger = logging.getLogger(__name__)

FDA_BASE = "https://api.fda.gov"
FDA_API_KEY = os.getenv("FDA_API_KEY", "")

# Mots-clés vasculaires — filtre côté client après requête sur advisory_committee:"CH"
# "CH" couvre tout le système circulatoire (pacemakers, valves, etc.)
# Ces mots-clés ciblent uniquement les dispositifs vasculaires chirurgicaux
_VASCULAR_KEYWORDS = [
    "aort",            # aortic, aorta, aorto-
    "endovascular",
    "endograft",
    "stent graft",
    "stentgraft",
    "fenestrated",
    "branched",
    "tevar",
    "evar",
    "fevar",
    "carotid",
    "iliac",
    "thoracic aneurysm",
    "abdominal aneurysm",
    "peripheral vascular",
    "peripheral arterial",
    "arteriovenous",
    "arterial graft",
    "vascular graft",
    "bypass graft",
    "inferior vena cava",
    "ivc filter",
    "thrombectomy",
    "embolectomy",
    "hemodialysis access",
    "dialysis access",
    "atherectomy",
    "angioplasty",
    "revascularization",
]


def _is_vascular(trade_name: str, generic_name: str) -> bool:
    """Retourne True si le dispositif est vasculaire selon les mots-clés."""
    text = f"{trade_name} {generic_name}".lower()
    return any(kw in text for kw in _VASCULAR_KEYWORDS)


def _fda_params(extra: dict) -> dict:
    """Paramètres de base pour les requêtes openFDA."""
    p: dict = {}
    if FDA_API_KEY:
        p["api_key"] = FDA_API_KEY
    p.update(extra)
    return p


def _date_range_filter(days: int) -> str:
    """Génère le filtre de date au format openFDA (YYYYMMDD)."""
    since = (date.today() - timedelta(days=days)).strftime("%Y%m%d")
    today = date.today().strftime("%Y%m%d")
    return f"[{since}+TO+{today}]"


# ---------------------------------------------------------------------------
# PMA (Class III — approbations implants vasculaires haute priorité)
# ---------------------------------------------------------------------------

def collect_fda_pma(days: int = 90) -> dict[str, int]:
    """
    Collecte les approbations PMA (Class III) pour dispositifs vasculaires.

    Returns:
        {"fetched": N, "inserted": N, "skipped": N, "errors": N}
    """
    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    date_filter = _date_range_filter(days)

    # Requête : comité CH (Circulatory System) + filtre date sur decision_date
    search_query = f'advisory_committee:"CH"+AND+decision_date:{date_filter}'
    params = _fda_params({
        "search": search_query,
        "limit": 100,
        "skip": 0,
    })

    results: list[dict] = []
    try:
        with httpx.Client(follow_redirects=True) as client:
            # Pagination : openFDA limite à 100 résultats par requête
            while True:
                r = client.get(f"{FDA_BASE}/device/pma.json", params=params, timeout=20)
                if r.status_code == 404:
                    # Aucun résultat pour cette période
                    break
                r.raise_for_status()
                data = r.json()
                batch = data.get("results", [])
                results.extend(batch)
                meta = data.get("meta", {}).get("results", {})
                total = meta.get("total", 0)
                skip = params["skip"] + len(batch)
                if skip >= total or len(batch) < 100:
                    break
                params["skip"] = skip
                time.sleep(0.3)
    except Exception as e:
        logger.warning("[fda_pma] fetch error: %s", e)
        return stats

    stats["fetched"] = len(results)

    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in results:
                try:
                    trade_name = item.get("trade_name") or ""
                    generic_name = item.get("generic_name") or ""

                    # Filtre vasculaire côté client
                    if not _is_vascular(trade_name, generic_name):
                        stats["skipped"] += 1
                        continue

                    pma_number = item.get("pma_number") or ""
                    if not pma_number:
                        stats["errors"] += 1
                        continue

                    decision_date_str = item.get("decision_date") or ""
                    try:
                        pub_date = date(
                            int(decision_date_str[:4]),
                            int(decision_date_str[4:6]),
                            int(decision_date_str[6:8]),
                        )
                    except (ValueError, IndexError):
                        pub_date = date.today()

                    applicant = item.get("applicant") or ""
                    decision = item.get("decision_description") or item.get("decision") or "Approved"
                    supplement_type = item.get("supplement_type") or ""

                    title = f"[FDA PMA] {trade_name} — {generic_name}"
                    if supplement_type:
                        title += f" ({supplement_type})"

                    content = (
                        f"Fabricant : {applicant}\n"
                        f"Décision : {decision}\n"
                        f"Numéro PMA : {pma_number}\n"
                        f"Type : {supplement_type or 'Original'}\n"
                        f"Dispositif : {generic_name}"
                    )

                    official_url = (
                        f"https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfpma/pma.cfm"
                        f"?id={pma_number}"
                    )

                    raw_payload = {
                        "pma_number": pma_number,
                        "trade_name": trade_name,
                        "generic_name": generic_name,
                        "applicant": applicant,
                        "decision_date": decision_date_str,
                        "decision": decision,
                        "supplement_type": supplement_type,
                        "advisory_committee": item.get("advisory_committee"),
                        "source": "fda_pma",
                        "source_type": "innovation",
                        "specialty_hint": "chirurgie-vasculaire",
                    }

                    row = build_candidate_row(
                        source="fda_pma",
                        external_id=pma_number,
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=content,
                        raw_payload=raw_payload,
                    )

                    inserted = insert_candidate(cur, row)
                    if inserted:
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1

                except Exception as e:
                    logger.warning("[fda_pma] insert error for %s: %s", item.get("pma_number"), e)
                    stats["errors"] += 1

        conn.commit()

    logger.info("[fda_pma] done — %s", stats)
    return stats


# ---------------------------------------------------------------------------
# 510(k) (Class II — clearances dispositifs vasculaires)
# ---------------------------------------------------------------------------

def collect_fda_510k(days: int = 90) -> dict[str, int]:
    """
    Collecte les clearances 510(k) (Class II) pour dispositifs vasculaires.

    Returns:
        {"fetched": N, "inserted": N, "skipped": N, "errors": N}
    """
    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    date_filter = _date_range_filter(days)

    # Filtre : comité CH + date de décision
    search_query = f'advisory_committee:"CH"+AND+decision_date:{date_filter}'
    params = _fda_params({
        "search": search_query,
        "limit": 100,
        "skip": 0,
    })

    results: list[dict] = []
    try:
        with httpx.Client(follow_redirects=True) as client:
            while True:
                r = client.get(f"{FDA_BASE}/device/510k.json", params=params, timeout=20)
                if r.status_code == 404:
                    break
                r.raise_for_status()
                data = r.json()
                batch = data.get("results", [])
                results.extend(batch)
                meta = data.get("meta", {}).get("results", {})
                total = meta.get("total", 0)
                skip = params["skip"] + len(batch)
                if skip >= total or len(batch) < 100:
                    break
                params["skip"] = skip
                time.sleep(0.3)
    except Exception as e:
        logger.warning("[fda_510k] fetch error: %s", e)
        return stats

    stats["fetched"] = len(results)

    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in results:
                try:
                    device_name = item.get("device_name") or ""
                    applicant = item.get("applicant") or item.get("contact") or ""

                    # Filtre vasculaire côté client
                    if not _is_vascular(device_name, ""):
                        stats["skipped"] += 1
                        continue

                    k_number = item.get("k_number") or ""
                    if not k_number:
                        stats["errors"] += 1
                        continue

                    decision_date_str = item.get("decision_date") or ""
                    try:
                        pub_date = date(
                            int(decision_date_str[:4]),
                            int(decision_date_str[4:6]),
                            int(decision_date_str[6:8]),
                        )
                    except (ValueError, IndexError):
                        pub_date = date.today()

                    decision_description = item.get("decision_description") or "Substantially Equivalent"

                    title = f"[FDA 510k] {device_name}"

                    content = (
                        f"Fabricant : {applicant}\n"
                        f"Décision : {decision_description}\n"
                        f"Numéro 510(k) : {k_number}\n"
                        f"Dispositif : {device_name}"
                    )

                    official_url = (
                        f"https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfpmn/pmn.cfm"
                        f"?ID={k_number}"
                    )

                    raw_payload = {
                        "k_number": k_number,
                        "device_name": device_name,
                        "applicant": applicant,
                        "decision_date": decision_date_str,
                        "decision_description": decision_description,
                        "advisory_committee": item.get("advisory_committee"),
                        "source": "fda_510k",
                        "source_type": "innovation",
                        "specialty_hint": "chirurgie-vasculaire",
                    }

                    row = build_candidate_row(
                        source="fda_510k",
                        external_id=k_number,
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=content,
                        raw_payload=raw_payload,
                    )

                    inserted = insert_candidate(cur, row)
                    if inserted:
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1

                except Exception as e:
                    logger.warning("[fda_510k] insert error for %s: %s", item.get("k_number"), e)
                    stats["errors"] += 1

        conn.commit()

    logger.info("[fda_510k] done — %s", stats)
    return stats


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def collect_all_fda(days: int = 90) -> dict[str, dict]:
    """Collecte PMA + 510(k) en séquence."""
    return {
        "fda_pma": collect_fda_pma(days=days),
        "fda_510k": collect_fda_510k(days=days),
    }
