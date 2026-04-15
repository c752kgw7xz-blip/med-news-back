# app/eudamed_collector.py
"""
Collecteur EUDAMED — dispositifs médicaux à marque CE (Commission Européenne).

Pourquoi c'est plus pertinent que FDA pour un chirurgien français :
  Un stent graft FDA-approuvé peut ne pas être disponible en France pendant des mois.
  L'approbation CE via EUDAMED est le signal réel de disponibilité en France et en Europe.

Source : base de données EUDAMED publique (European Union Medical Device Database)
  https://ec.europa.eu/tools/eudamed/

API REST publique :
  POST https://ec.europa.eu/tools/eudamed/api/devices/basicUDI/search
  Pas d'authentification pour la lecture.
  Rate limit : non documenté — on reste conservatif (0.5s entre requêtes).

Filtre :
  1. Type de dispositif = "MD" (Medical Device, pas IVD)
  2. Classe de risque = "Im" (Classe III — implants haute priorité)
  3. Date de création ou modification récente (filtre côté API si disponible,
     sinon filtrage côté client sur le champ `createdDate` / `modifiedDate`)
  4. Mots-clés vasculaires côté client (même liste que FDA collector)

Références EUDAMED :
  - Swagger : https://ec.europa.eu/tools/eudamed/swagger-ui/index.html
  - Nomenclature EMDN : codes commençant par E (cardiovasculaire)
    E06 = Prothèses vasculaires non cardiaques (stent grafts, greffons)
    E07 = Dispositifs vasculaires périphériques (stents, ballons, filtres)

Note : l'API EUDAMED peut évoluer. Vérifier le swagger en cas d'erreur 404/422.
"""

from __future__ import annotations

import logging
import time
from datetime import date, timedelta
from typing import Any

import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn

logger = logging.getLogger(__name__)

EUDAMED_BASE = "https://ec.europa.eu/tools/eudamed/api"

# Codes EMDN vasculaires — European Medical Device Nomenclature
# E06 : Prothèses vasculaires non cardiaques (stent grafts, patches, greffons)
# E07 : Dispositifs vasculaires périphériques (stents, cathéters, ballons, filtres)
# E05 : Implants cardiaques ET vasculaires (pontage, valves — inclus pour débord)
_VASCULAR_EMDN_CODES = ["E05", "E06", "E07"]

# Mots-clés vasculaires pour filtre côté client (même logique que fda_collector)
_VASCULAR_KEYWORDS = [
    "aort",
    "endovascular",
    "endograft",
    "stent graft",
    "stentgraft",
    "fenestrated",
    "branched",
    "carotid",
    "iliac",
    "thoracic",
    "abdominal aneurysm",
    "peripheral vascular",
    "peripheral arterial",
    "arteriovenous",
    "arterial graft",
    "vascular graft",
    "bypass graft",
    "inferior vena cava",
    "vena cava filter",
    "ivc filter",
    "thrombectomy",
    "embolectomy",
    "hemodialysis",
    "dialysis access",
    "atherectomy",
    "angioplasty",
    "revascularization",
    "endoprothèse",
    "prothèse vasculaire",
    "greffon vasculaire",
    "filtre cave",
    "stent périphérique",
]


def _is_vascular(name: str, description: str = "") -> bool:
    """Retourne True si le dispositif est vasculaire selon les mots-clés."""
    text = f"{name} {description}".lower()
    return any(kw in text for kw in _VASCULAR_KEYWORDS)


def _format_date(d: date) -> str:
    return d.strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Collecteur EUDAMED — Classe III implants vasculaires
# ---------------------------------------------------------------------------

def collect_eudamed_devices(days: int = 90) -> dict[str, int]:
    """
    Collecte les dispositifs médicaux CE de classe III dans les catégories vasculaires.

    Stratégie :
      1. Requête par code EMDN vasculaire (E06, E07) en POST sur l'API EUDAMED
      2. Filtre côté client sur la date de création/modification
      3. Filtre côté client sur les mots-clés vasculaires si le code EMDN n'est pas suffisant

    Returns:
        {"fetched": N, "inserted": N, "skipped": N, "errors": N}
    """
    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}
    since = date.today() - timedelta(days=days)

    all_items: list[dict] = []

    with httpx.Client(
        follow_redirects=True,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "med-news-back/1.0 (contact@mednews.fr)",
        },
    ) as client:
        for emdn_code in _VASCULAR_EMDN_CODES:
            items = _search_eudamed_by_emdn(client, emdn_code, since)
            all_items.extend(items)
            time.sleep(0.5)

    stats["fetched"] = len(all_items)

    if not all_items:
        logger.info("[eudamed] aucun dispositif trouvé pour les %d derniers jours", days)
        return stats

    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in all_items:
                try:
                    _process_eudamed_item(cur, item, since, stats)
                except Exception as e:
                    logger.warning("[eudamed] insert error: %s", e)
                    stats["errors"] += 1
        conn.commit()

    logger.info("[eudamed] done — %s", stats)
    return stats


def _search_eudamed_by_emdn(
    client: httpx.Client,
    emdn_code: str,
    since: date,
) -> list[dict]:
    """
    Requête EUDAMED pour un code EMDN donné.
    Retourne les résultats bruts de l'API.
    """
    all_results: list[dict] = []
    page = 1
    page_size = 100

    while True:
        # Corps de requête POST — format EUDAMED basicUDI/search
        payload = {
            "pageNumber": page,
            "pageSize": page_size,
            "filters": {
                "groupMedicalDeviceType": "MD",           # Medical Device (pas IVD)
                "riskClassification": ["Im"],             # Classe III implants
                "emdn": emdn_code,                        # Code nomenclature vasculaire
            },
        }

        try:
            r = client.post(
                f"{EUDAMED_BASE}/devices/basicUDI/search",
                json=payload,
                timeout=20,
            )

            if r.status_code == 404:
                # Endpoint ou paramètre invalide — log et abandon silencieux
                logger.warning(
                    "[eudamed] 404 pour EMDN=%s — vérifier le swagger EUDAMED", emdn_code
                )
                break
            if r.status_code == 422:
                logger.warning(
                    "[eudamed] 422 pour EMDN=%s — paramètre de requête invalide : %s",
                    emdn_code, r.text[:200],
                )
                break

            r.raise_for_status()
            data = r.json()

        except httpx.HTTPStatusError as e:
            logger.warning("[eudamed] HTTP error EMDN=%s: %s", emdn_code, e)
            break
        except Exception as e:
            logger.warning("[eudamed] fetch error EMDN=%s: %s", emdn_code, e)
            break

        # L'API EUDAMED peut retourner les résultats dans "data", "results" ou "content"
        batch: list[dict] = (
            data.get("data")
            or data.get("results")
            or data.get("content")
            or []
        )
        if not batch:
            break

        all_results.extend(batch)

        # Pagination
        total = (
            data.get("totalElements")
            or data.get("total")
            or data.get("totalCount")
            or 0
        )
        if len(all_results) >= total or len(batch) < page_size:
            break

        page += 1
        time.sleep(0.5)

    return all_results


def _process_eudamed_item(
    cur: Any,
    item: dict,
    since: date,
    stats: dict,
) -> None:
    """
    Traite un item EUDAMED et l'insère en base si pertinent.
    Les champs EUDAMED peuvent varier selon la version de l'API — on est défensif.
    """
    # Identifiant unique EUDAMED — plusieurs formats possibles
    eudamed_id = (
        item.get("basicUdiDiId")
        or item.get("id")
        or item.get("udiDi")
        or item.get("basicUDIDI")
        or ""
    )
    if not eudamed_id:
        stats["errors"] += 1
        return

    # Nom du dispositif
    device_name = (
        item.get("deviceName")
        or item.get("name")
        or item.get("tradeNames", [{}])[0].get("deviceName", "") if item.get("tradeNames") else ""
        or ""
    )
    if not device_name:
        device_name = "(dispositif sans nom)"

    # Description / nomenclature
    description = (
        item.get("shortDescription")
        or item.get("description")
        or item.get("emdn", {}).get("description", "") if isinstance(item.get("emdn"), dict) else ""
        or ""
    )

    # Fabricant
    manufacturer = (
        item.get("manufacturer", {}).get("name", "") if isinstance(item.get("manufacturer"), dict)
        else item.get("manufacturerName", "")
        or ""
    )

    # Date de création / mise sur le marché CE
    date_str = (
        item.get("createdDate")
        or item.get("dateOfCertificate")
        or item.get("certificateDate")
        or ""
    )
    pub_date = since  # fallback
    if date_str:
        try:
            pub_date = date.fromisoformat(date_str[:10])
        except (ValueError, TypeError):
            pass

    # Filtre date côté client
    if pub_date < since:
        stats["skipped"] += 1
        return

    # Filtre vasculaire côté client
    if not _is_vascular(device_name, description):
        stats["skipped"] += 1
        return

    # Classe de risque
    risk_class = item.get("riskClassification") or item.get("riskClass") or "III"

    # URL EUDAMED publique
    official_url = (
        f"https://ec.europa.eu/tools/eudamed/#/screen/devices/udi-di/"
        f"{eudamed_id}"
    )

    title = f"[CE] {device_name}"
    if manufacturer:
        title += f" — {manufacturer}"

    content = (
        f"Fabricant : {manufacturer}\n"
        f"Classe : {risk_class}\n"
        f"Description : {description or device_name}\n"
        f"ID EUDAMED : {eudamed_id}"
    )

    raw_payload = {
        **item,
        "source": "eudamed",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
    }

    row = build_candidate_row(
        source="eudamed",
        external_id=str(eudamed_id),
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
