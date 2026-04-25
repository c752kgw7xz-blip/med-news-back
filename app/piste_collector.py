# app/piste_collector.py
"""
Collecteurs PISTE pour les fonds réglementaires médicaux.

Fonds retenus :
  JORF → collect_jorf()  : Journal Officiel — décrets, arrêtés, avis médicaux
  KALI → collect_kali()  : convention médicale UNCAM, avenants tarifaires

Fonds supprimés :
  CIRCULAIRES → doublon du BO Social, moins fiable
  LEGI        → modifications techniques, doublon tardif du JORF

Point d'entrée global : collect_all_piste_fonds(days) → JORF + KALI
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
    # Paramédicaux — conventions et avenants kiné, IDEL, sages-femmes
    "kinésithér", "infirmier", "infirmière", "sage-femme", "sages-femmes",
    "auxiliaire médical", "masseur",
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
            for page in range(1, 41):
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
                    try:
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
                    except Exception as e:
                        logger.warning("[%s] erreur item : %s", source, e)
                        skipped += 1

        conn.commit()

    logger.info("[%s] vu=%d ins=%d dup=%d ign=%d", source, seen, inserted, deduped, skipped)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ---------------------------------------------------------------------------
# JORF — Journal Officiel de la République Française
# ---------------------------------------------------------------------------

def collect_jorf(days: int = 35) -> dict[str, int]:
    """
    Collecte les textes JORF (Journal Officiel) via l'API PISTE.

    Filtre sur les natures réglementaires médicales (décrets, arrêtés, avis…)
    via _keep_item_with_reason. Remonte les textes publiés dans la fenêtre
    [today - days, today].
    """
    from app.piste_routes import (
        _piste_call, _extract_list, _keep_item_with_reason,
        _parse_date10, _official_url,
    )

    source = "legifrance_jorf"
    today = date.today()
    start = today - timedelta(days=days)
    seen = ins = dup = 0

    logger.info("=== Collecte JORF (%d jours) ===", days)

    with get_conn() as conn:
        with conn.cursor() as cur:
            for page in range(1, 41):
                payload = {"fond": "JORF", "recherche": {
                    "pageNumber": page, "pageSize": 50,
                    "operateur": "ET", "typePagination": "DEFAUT",
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
                        official_date=pub_d,
                        title_raw=(title or "").strip() or "(no title)",
                        jorftext_id=jorftext_id, raw_payload=it,
                    )
                    if insert_candidate(cur, row):
                        ins += 1
                    else:
                        dup += 1
        conn.commit()

    logger.info("[%s] vu=%d ins=%d dup=%d", source, seen, ins, dup)
    return {"seen": seen, "inserted": ins, "deduped": dup}


# ---------------------------------------------------------------------------
# Collecteur global PISTE
# ---------------------------------------------------------------------------

def collect_all_piste_fonds(days: int = 35) -> dict[str, Any]:
    """Lance la collecte de tous les fonds PISTE : JORF + KALI."""
    results = {}
    try:
        results["jorf"] = collect_jorf(days=days)
    except Exception as e:
        logger.error("Collecte JORF échouée : %s", e)
        results["jorf"] = {"error": str(e)}
    try:
        results["kali"] = collect_kali(days=days)
    except Exception as e:
        logger.error("Collecte KALI échouée : %s", e)
        results["kali"] = {"error": str(e)}
    return results
