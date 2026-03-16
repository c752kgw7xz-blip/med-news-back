# app/collector_utils.py
"""
Utilitaires partagés par tous les collecteurs (PISTE, RSS).

Fournit :
  - INSERT_CANDIDATE_SQL  : requête d'insertion avec déduplication
  - insert_candidate()    : insère un candidat normalisé en base
  - CandidateRow          : TypedDict décrivant le format attendu
  - sha256_hex()          : hash stable
  - canonical_json_bytes(): sérialisation déterministe pour le hash
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Any, TypedDict

from psycopg.types.json import Json

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

INSERT_CANDIDATE_SQL = """
INSERT INTO candidates (
    source,
    official_url,
    official_date,
    title_raw,
    pdf_url,
    content_raw,
    raw_sha256,
    dedupe_key,
    status,
    jorftext_id,
    raw_json
)
VALUES (
    %(source)s,
    %(official_url)s,
    %(official_date)s,
    %(title_raw)s,
    %(pdf_url)s,
    %(content_raw)s,
    %(raw_sha256)s,
    %(dedupe_key)s,
    'NEW',
    %(jorftext_id)s,
    %(raw_json)s
)
ON CONFLICT (dedupe_key) DO NOTHING;
"""


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class CandidateRow(TypedDict):
    source: str
    official_url: str
    official_date: date
    title_raw: str
    pdf_url: str | None
    content_raw: str | None
    raw_sha256: str
    dedupe_key: str
    jorftext_id: str | None
    raw_json: Any   # sera wrappé en Json()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def make_dedupe_key(source: str, external_id: str) -> str:
    return sha256_hex(f"{source}|{external_id}")


def build_candidate_row(
    *,
    source: str,
    external_id: str,
    official_url: str,
    official_date: date,
    title_raw: str,
    pdf_url: str | None = None,
    content_raw: str | None = None,
    jorftext_id: str | None = None,
    raw_payload: Any = None,
) -> CandidateRow:
    """
    Construit un CandidateRow prêt à insérer.
    raw_payload : dict brut de la source (pour traçabilité).
    """
    raw_payload = raw_payload or {}
    raw_bytes = canonical_json_bytes(raw_payload)

    return CandidateRow(
        source=source,
        official_url=official_url,
        official_date=official_date,
        title_raw=(title_raw or "").strip() or "(sans titre)",
        pdf_url=pdf_url,
        content_raw=content_raw,
        raw_sha256=sha256_hex(raw_bytes),
        dedupe_key=make_dedupe_key(source, external_id),
        jorftext_id=jorftext_id,
        raw_json=raw_payload,
    )


def insert_candidate(cur: Any, row: CandidateRow) -> bool:
    """
    Insère un candidat via le curseur psycopg fourni.
    Retourne True si inséré, False si doublon.
    Le commit est à la charge de l'appelant.
    """
    params = dict(row)
    params["raw_json"] = Json(row["raw_json"])
    cur.execute(INSERT_CANDIDATE_SQL, params)
    return cur.rowcount == 1
