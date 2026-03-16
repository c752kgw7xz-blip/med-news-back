# app/piste_collector.py
"""
Collecteurs PISTE pour les fonds réglementaires médicaux.

Fonds retenus :
  JORF        → traité directement dans scheduler.py (existant)
  KALI        → convention médicale UNCAM, avenants tarifaires
  CIRCULAIRES → supprimé (doublon du BO Social, moins fiable)
  LEGI        → supprimé (modifications techniques, doublon tardif du JORF)

Seul KALI est implémenté ici. Le JORF reste dans scheduler.py
pour ne pas casser le pipeline existant.
"""

from __future__ import annotations

import logging
import re
from datetime import date, timedelta
from typing import Any

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn
from app.piste_client import piste_post

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _piste_call_safe(path: str, payload: dict) -> Any:
    try:
        return piste_post(path, payload)
    except Exception as e:
        logger.warning("PISTE %s échoué : %s", path, e)
        return None


def _extract_items(data: Any) -> list[dict]:
    if isinstance(data, dict):
        for key in ("results", "list", "hits", "data"):
            v = data.get(key)
            if isinstance(v, list) and v:
                return v
    if isinstance(data, list):
        return data
    return []


_FR_MONTHS = {
    "janvier": 1, "février": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
    "juillet": 7, "août": 8, "septembre": 9, "octobre": 10, "novembre": 11,
    "décembre": 12,
}
_FR_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+(" + "|".join(_FR_MONTHS) + r")\s+(\d{4})\b",
    re.IGNORECASE,
)


def _parse_date(v: Any) -> date | None:
    if not isinstance(v, str) or len(v) < 10:
        return None
    try:
        d = date.fromisoformat(v[:10])
        # Rejette les dates symboliques (2999-01-01 = "toujours en vigueur" dans KALI)
        if d.year > date.today().year + 1:
            return None
        return d
    except ValueError:
        return None


def _parse_date_from_title(title: str) -> date | None:
    """Extrait la date d'un titre KALI de type 'Avenant n° 11 du 16 mars 2023 relatif à...'"""
    m = _FR_DATE_RE.search(title)
    if not m:
        return None
    try:
        day   = int(m.group(1))
        month = _FR_MONTHS[m.group(2).lower()]
        year  = int(m.group(3))
        return date(year, month, day)
    except (ValueError, KeyError):
        return None


def _title_from_item(it: dict) -> str:
    for key in ("titre", "title", "titreTexte", "norTitre", "intitule", "libelle"):
        v = it.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    titles = it.get("titles")
    if isinstance(titles, list) and titles:
        t0 = titles[0]
        if isinstance(t0, dict):
            v = t0.get("title") or t0.get("titre")
            if isinstance(v, str) and v.strip():
                return v.strip()
    return "(sans titre)"


def _pub_date_from_item(it: dict, title: str = "") -> date | None:
    for key in ("dateSignature", "dateDiffusion", "dateTexte", "dateDebut",
                "datePublication", "datePubli", "publicationDate", "date"):
        d = _parse_date(it.get(key))
        if d:
            return d
    # Fallback : extrait la date depuis le titre (ex: "Avenant n° 11 du 16 mars 2023...")
    if title:
        return _parse_date_from_title(title)
    return None


def _external_id_from_item(it: dict) -> str | None:
    titles = it.get("titles") if isinstance(it.get("titles"), list) else []
    t0 = titles[0] if titles and isinstance(titles[0], dict) else {}
    return (
        t0.get("cid")
        or it.get("id")
        or it.get("cid")
        or it.get("nor")
        or it.get("textId")
    )


# ---------------------------------------------------------------------------
# KALI — Convention médicale et avenants UNCAM
# ---------------------------------------------------------------------------

# Mots-clés qui signalent un texte KALI pertinent pour la médecine libérale
KALI_KEYWORDS = [
    "médecin", "médecins", "médical", "médicale",
    "convention nationale", "tarif", "honoraires",
    "acte", "cotation", "remboursement", "avenant",
    "secteur", "omnipraticien", "généraliste", "spécialiste",
    "libéral", "libéraux", "ccam", "ngap",
]


def _kali_filter(title: str) -> bool:
    t = title.lower()
    return any(kw in t for kw in KALI_KEYWORDS)


def collect_kali(days: int = 35) -> dict[str, int]:
    """
    Collecte les avenants et accords KALI relatifs à la médecine libérale.

    Le fonds KALI contient les conventions collectives nationales.
    On filtre sur les textes qui touchent explicitement les médecins libéraux :
    convention nationale, honoraires, actes, cotations CCAM/NGAP, avenants UNCAM.
    """
    logger.info("=== Collecte KALI (convention médicale UNCAM) ===")

    today = date.today()
    start = today - timedelta(days=days)
    source = "piste_kali"

    seen = inserted = deduped = skipped = 0

    with get_conn() as conn:
        with conn.cursor() as cur:
            for page in range(1, 21):
                payload = {
                    "fond": "KALI",
                    "recherche": {
                        "pageNumber": page,
                        "pageSize": 50,
                        "operateur": "ET",
                        "typePagination": "DEFAUT",
                    },
                }
                data = _piste_call_safe("/search", payload)
                if data is None:
                    break

                items = _extract_items(data)
                if not items:
                    break

                for it in items:
                    if not isinstance(it, dict):
                        continue
                    seen += 1

                    title = _title_from_item(it)
                    pub_date = _pub_date_from_item(it, title)

                    if pub_date is None or not (start <= pub_date <= today):
                        skipped += 1
                        continue

                    if not _kali_filter(title):
                        skipped += 1
                        continue

                    ext_id = _external_id_from_item(it)
                    if not ext_id:
                        skipped += 1
                        continue

                    official_url = f"https://www.legifrance.gouv.fr/conv_coll/id/{ext_id}"

                    row = build_candidate_row(
                        source=source,
                        external_id=str(ext_id),
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        raw_payload=it,
                    )

                    if insert_candidate(cur, row):
                        inserted += 1
                    else:
                        deduped += 1

        conn.commit()

    logger.info("[%s] vu=%d ins=%d dup=%d ign=%d", source, seen, inserted, deduped, skipped)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ---------------------------------------------------------------------------
# Collecteur global PISTE (hors JORF déjà dans scheduler.py)
# ---------------------------------------------------------------------------

def collect_all_piste_fonds(days: int = 35) -> dict[str, Any]:
    """
    Lance la collecte des fonds PISTE complémentaires.
    Le JORF est géré séparément dans scheduler.py.
    """
    results = {}
    try:
        results["kali"] = collect_kali(days=days)
    except Exception as e:
        logger.error("Collecte KALI échouée : %s", e)
        results["kali"] = {"error": str(e)}
    return results
