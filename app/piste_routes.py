# app/piste_routes.py
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import date, timedelta
from typing import Any

import psycopg
from psycopg.types.json import Json
from fastapi import APIRouter, HTTPException, Request

from app.piste_client import piste_post  # type: ignore

router = APIRouter(prefix="/admin/piste", tags=["piste"])


# ----------------------
# Auth (admin secret)
# ----------------------
def _require_admin(request: Request) -> None:
    expected = os.environ.get("ADMIN_SECRET")
    got = request.headers.get("x-admin-secret")
    if not expected or got != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


# ----------------------
# DB
# ----------------------
def _get_conn() -> psycopg.Connection:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise HTTPException(status_code=501, detail="DATABASE_URL not set")
    return psycopg.connect(dsn)


# ----------------------
# Safe PISTE call wrapper (surface real errors)
# ----------------------
def _piste_call(path: str, payload: dict[str, Any]) -> Any:
    if piste_post is None:
        raise HTTPException(status_code=501, detail="piste_post not installed")

    try:
        return piste_post(path, payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"PISTE call failed on {path}: {type(e).__name__}: {e}",
        )


# ----------------------
# Helpers
# ----------------------
def _is_id(v: Any, prefix: str) -> bool:
    return isinstance(v, str) and v.startswith(prefix)


def _extract_list(payload: Any) -> list[Any]:
    if isinstance(payload, dict):
        return (
            payload.get("results")
            or payload.get("list")
            or payload.get("hits")
            or payload.get("data")
            or []
        )
    if isinstance(payload, list):
        return payload
    return []


def _parse_date10(v: Any) -> str | None:
    if isinstance(v, str) and len(v) >= 10:
        try:
            date.fromisoformat(v[:10])
            return v[:10]
        except Exception:
            return None
    return None


def _parse_date(v: Any) -> date | None:
    s = _parse_date10(v)
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except Exception:
        return None


def _pick_container_ids(last_payload: Any) -> list[str]:
    items: list[Any] = []
    if isinstance(last_payload, dict):
        items = (
            last_payload.get("results")
            or last_payload.get("list")
            or last_payload.get("jorfConts")
            or last_payload.get("data")
            or []
        )
    elif isinstance(last_payload, list):
        items = last_payload

    out: list[str] = []
    if isinstance(items, list):
        for x in items:
            if _is_id(x, "JORFCONT"):
                out.append(x)
            elif isinstance(x, dict):
                cid = x.get("id") or x.get("jorfContId") or x.get("jorfCont") or x.get("containerId")
                if _is_id(cid, "JORFCONT"):
                    out.append(cid)

    seen = set()
    uniq: list[str] = []
    for c in out:
        if c not in seen:
            uniq.append(c)
            seen.add(c)
    return uniq


def _pick_text_ids(cont_payload: Any) -> list[str]:
    items: list[Any] = []
    if isinstance(cont_payload, dict):
        items = (
            cont_payload.get("results")
            or cont_payload.get("list")
            or cont_payload.get("texts")
            or cont_payload.get("data")
            or []
        )
    elif isinstance(cont_payload, list):
        items = cont_payload

    out: list[str] = []
    if isinstance(items, list):
        for it in items:
            if _is_id(it, "JORFTEXT"):
                out.append(it)
            elif isinstance(it, dict):
                tid = (
                    it.get("id")
                    or it.get("jorfTextId")
                    or it.get("textId")
                    or it.get("jorfText")
                    or it.get("jorf")
                )
                if _is_id(tid, "JORFTEXT"):
                    out.append(tid)

    seen = set()
    uniq: list[str] = []
    for t in out:
        if t not in seen:
            uniq.append(t)
            seen.add(t)
    return uniq


def _parse_pub_date(detail: dict[str, Any]) -> date | None:
    candidates = [
        detail.get("datePublication"),
        detail.get("datePubli"),
        detail.get("publicationDate"),
        detail.get("date"),
        detail.get("dateSignature"),
        detail.get("dateTexte"),
    ]
    for v in candidates:
        d = _parse_date(v)
        if d:
            return d

    for k, v in detail.items():
        if "date" in k.lower():
            d = _parse_date(v)
            if d:
                return d
    return None


def _title(detail: dict[str, Any]) -> str:
    return (
        detail.get("title")
        or detail.get("titre")
        or detail.get("norTitre")
        or detail.get("titreTexte")
        or ""
    )


def _pdf_url(detail: dict[str, Any]) -> str | None:
    v = detail.get("pdfUrl") or detail.get("pdf") or detail.get("pdf_url")
    return v if isinstance(v, str) and v else None


def _official_url(jorftext_id: str) -> str:
    return f"https://www.legifrance.gouv.fr/jorf/id/{jorftext_id}"


def _json_canonical_bytes(obj: Any) -> bytes:
    # stable hashing independent of key order / whitespace
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ----------------------
# Filtering rules (anti-bruit métier)
# ----------------------
KEEP_NATURE = {"ARRETE", "DECRET", "LOI", "ORDONNANCE"}
DROP_NATURE = {"INFORMATIONS_PARLEMENTAIRES"}

DROP_TITLE_CONTAINS = [
    "avis de vacance",
    "documents déposés",
    "résultats",
    "cote & score",
]


def _keep_item_with_reason(nature: Any, title: Any) -> tuple[bool, str | None]:
    n = (nature or "").strip()
    t = (title or "").strip().lower()

    if n in DROP_NATURE:
        return False, "drop_nature"
    if KEEP_NATURE and n not in KEEP_NATURE:
        return False, "not_in_keep_nature"
    for bad in DROP_TITLE_CONTAINS:
        if bad in t:
            return False, "drop_title_contains"
    return True, None


# ----------------------
# Routes (READ-ONLY)
# ----------------------
@router.post("/jorf/last-7-days")
def jorf_last_7_days(
    request: Request,
    nb_jo: int = 50,
    page_size: int = 200,
    limit: int = 200,
):
    """
    READ-ONLY.
    Strategy: lastNJo -> each JORFCONT -> list JORFTEXT -> detail (/consult/jorf) -> filter on date in last 7 days.
    NOTE: In SANDBOX, lastNJo may return no containers -> count=0 (expected).
    """
    _require_admin(request)

    today = date.today()
    start = today - timedelta(days=7)

    last = _piste_call("/consult/lastNJo", {"nbElement": nb_jo})
    cont_ids = _pick_container_ids(last)

    out: list[dict[str, Any]] = []
    errors = 0
    skipped_no_date = 0

    for cont_id in cont_ids:
        if len(out) >= limit:
            break

        cont = _piste_call(
            "/consult/jorfCont",
            {
                "highlightActivated": False,
                "id": cont_id,
                "pageNumber": 1,
                "pageSize": page_size,
            },
        )
        text_ids = _pick_text_ids(cont)

        for tid in text_ids:
            if len(out) >= limit:
                break

            try:
                detail = _piste_call("/consult/jorf", {"highlightActivated": False, "id": tid})
            except HTTPException:
                errors += 1
                continue

            if not isinstance(detail, dict):
                errors += 1
                continue

            pub = _parse_pub_date(detail)
            if pub is None:
                skipped_no_date += 1
                continue

            if not (start <= pub <= today):
                continue

            out.append(
                {
                    "jorftext_id": tid,
                    "date_publication": pub.isoformat(),
                    "titre": _title(detail),
                    "pdf_url": _pdf_url(detail),
                    "official_url": _official_url(tid),
                }
            )

    return {
        "ok": True,
        "from": start.isoformat(),
        "to": today.isoformat(),
        "containers": len(cont_ids),
        "count": len(out),
        "skipped_no_date": skipped_no_date,
        "errors": errors,
        "results": out,
    }


@router.post("/jorf/debug-sample")
def jorf_debug_sample(request: Request):
    """
    READ-ONLY debug endpoint for lastNJo path.
    Useful to confirm sandbox has no containers.
    """
    _require_admin(request)

    last = _piste_call("/consult/lastNJo", {"nbElement": 5})
    cont_ids = _pick_container_ids(last)

    if not cont_ids:
        return {"ok": True, "note": "no containers extracted", "last_type": str(type(last))}

    cont = _piste_call(
        "/consult/jorfCont",
        {"highlightActivated": False, "id": cont_ids[0], "pageNumber": 1, "pageSize": 5},
    )
    text_ids = _pick_text_ids(cont)

    if not text_ids:
        return {"ok": True, "containers": cont_ids, "note": "no text ids extracted from first container"}

    tid = text_ids[0]
    detail = _piste_call("/consult/jorf", {"highlightActivated": False, "id": tid})

    if not isinstance(detail, dict):
        return {"ok": True, "sample_text_id": tid, "detail_type": str(type(detail))}

    parsed = _parse_pub_date(detail)
    date_fields = {k: v for k, v in detail.items() if "date" in k.lower()}

    return {
        "ok": True,
        "sample_container_id": cont_ids[0],
        "sample_text_id": tid,
        "title": _title(detail),
        "parsed_pub_date": (parsed.isoformat() if parsed else None),
        "date_fields": date_fields,
        "detail_keys_sample": sorted(list(detail.keys()))[:120],
    }


# ----------------------
# Routes (READ-ONLY, SANDBOX-FRIENDLY)
# ----------------------
@router.post("/jorf/search-sample")
def jorf_search_sample(
    request: Request,
    page_number: int = 1,
    page_size: int = 10,
    strict: bool = False,
):
    """
    READ-ONLY. Sandbox-friendly.
    IMPORTANT: /search requires nested "recherche".
    strict=false (default): no anti-noise filter (debug-friendly).
    strict=true: applies anti-noise filter + stats.
    """
    _require_admin(request)

    payload = {
        "fond": "JORF",
        "recherche": {
            "pageNumber": page_number,
            "pageSize": page_size,
            "operateur": "ET",
            "typePagination": "DEFAUT",
        },
    }

    data = _piste_call("/search", payload)
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail={"msg": "unexpected response type", "type": str(type(data))})

    items = _extract_list(data)

    results: list[dict[str, Any]] = []
    dropped = 0
    drop_reasons: Counter[str] = Counter()

    for it in items:
        if not isinstance(it, dict):
            continue

        titles = it.get("titles") if isinstance(it.get("titles"), list) else []
        t0 = titles[0] if titles and isinstance(titles[0], dict) else {}

        jorftext_id = t0.get("cid")
        title = t0.get("title")
        nature = it.get("nature") or it.get("type")

        if strict:
            ok, reason = _keep_item_with_reason(nature, title)
            if not ok:
                dropped += 1
                if reason:
                    drop_reasons[reason] += 1
                continue

        date_pub = _parse_date10(it.get("datePublication")) or _parse_date10(it.get("date"))
        official_url = (
            _official_url(jorftext_id)
            if isinstance(jorftext_id, str) and jorftext_id.startswith("JORFTEXT")
            else None
        )

        results.append(
            {
                "jorftext_id": jorftext_id,
                "titre": title,
                "date_publication": date_pub,
                "nature": nature,
                "nor": it.get("nor"),
                "official_url": official_url,
            }
        )

    return {
        "ok": True,
        "strict": strict,
        "pageNumber": page_number,
        "pageSize": page_size,
        "items_count": len(items),
        "kept_count": len(results),
        "dropped_count": dropped,
        "dropped_reasons": dict(drop_reasons.most_common(10)),
        "results": results,
        "raw_keys": sorted(list(data.keys())),
    }


@router.post("/jorf/search-debug")
def jorf_search_debug(request: Request):
    """
    READ-ONLY debug endpoint for /search.
    Returns first raw item to adapt parsing if needed.
    """
    _require_admin(request)

    data = _piste_call(
        "/search",
        {
            "fond": "JORF",
            "recherche": {
                "pageNumber": 1,
                "pageSize": 3,
                "operateur": "ET",
                "typePagination": "DEFAUT",
            },
        },
    )

    if not isinstance(data, dict):
        return {"ok": False, "type": str(type(data))}

    items = _extract_list(data)
    sample = items[0] if items else None

    return {
        "ok": True,
        "data_keys": sorted(list(data.keys())),
        "items_count": len(items),
        "sample_item": sample,
        "sample_item_keys": sorted(list(sample.keys())) if isinstance(sample, dict) else None,
    }


# ----------------------
# Routes (WRITE) — /search -> candidates (dedupe-safe)
# ----------------------
@router.post("/jorf/search-to-candidates")
def jorf_search_to_candidates(
    request: Request,
    days: int = 90,
    strict: bool = True,
    page_size: int = 50,
    max_pages: int = 40,
):
    """
    WRITE into candidates.
    - pages through /search
    - optional strict anti-noise filter
    - filters official_date in [today-days, today]
    - inserts with ON CONFLICT (dedupe_key) DO NOTHING
    Never sets SELECTED/PUBLISHED here.
    """
    _require_admin(request)

    if days <= 0 or days > 3650:
        raise HTTPException(status_code=400, detail="invalid days")
    if page_size <= 0 or page_size > 200:
        raise HTTPException(status_code=400, detail="invalid page_size")
    if max_pages <= 0 or max_pages > 200:
        raise HTTPException(status_code=400, detail="invalid max_pages")

    today = date.today()
    start = today - timedelta(days=days)

    source = "legifrance_jorf"

    seen = 0
    kept_after_strict = 0
    kept_in_window = 0
    inserted = 0
    deduped = 0
    pages_fetched = 0
    stop_reason: str | None = None

    dropped_reasons: Counter[str] = Counter()

    insert_sql = """
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

    with _get_conn() as conn:
        with conn.cursor() as cur:
            for page_number in range(1, max_pages + 1):
                pages_fetched += 1

                payload = {
                    "fond": "JORF",
                    "recherche": {
                        "pageNumber": page_number,
                        "pageSize": page_size,
                        "operateur": "ET",
                        "typePagination": "DEFAUT",
                    },
                }

                data = _piste_call("/search", payload)
                if not isinstance(data, dict):
                    raise HTTPException(
                        status_code=502,
                        detail={"msg": "unexpected /search response type", "type": str(type(data))},
                    )

                items = _extract_list(data)
                if not items:
                    stop_reason = "empty_page"
                    break

                any_in_window = False

                for it in items:
                    if not isinstance(it, dict):
                        continue

                    seen += 1

                    titles = it.get("titles") if isinstance(it.get("titles"), list) else []
                    t0 = titles[0] if titles and isinstance(titles[0], dict) else {}

                    jorftext_id = t0.get("cid")
                    title = t0.get("title")
                    nature = it.get("nature") or it.get("type")

                    if strict:
                        ok, reason = _keep_item_with_reason(nature, title)
                        if not ok:
                            if reason:
                                dropped_reasons[reason] += 1
                            continue

                    kept_after_strict += 1

                    pub_s = _parse_date10(it.get("datePublication")) or _parse_date10(it.get("date"))
                    if not pub_s:
                        dropped_reasons["no_date"] += 1
                        continue

                    pub_d = date.fromisoformat(pub_s)
                    if pub_d < start or pub_d > today:
                        continue

                    any_in_window = True
                    kept_in_window += 1

                    if not (isinstance(jorftext_id, str) and jorftext_id.startswith("JORFTEXT")):
                        dropped_reasons["no_jorftext_id"] += 1
                        continue

                    official_url = _official_url(jorftext_id)

                    # dedupe stable per source + id
                    dedupe_key = _sha256_hex(f"{source}|{jorftext_id}".encode("utf-8"))

                    # raw traceability
                    raw_bytes = _json_canonical_bytes(it)
                    raw_sha256 = _sha256_hex(raw_bytes)

                    # content_raw: keep empty for now (detail fetch via /consult/jorf can fill later)
                    params = {
                        "source": source,
                        "official_url": official_url,
                        "official_date": pub_d,
                        "title_raw": (title or "").strip() or "(no title)",
                        "pdf_url": None,
                        "content_raw": None,
                        "raw_sha256": raw_sha256,
                        "dedupe_key": dedupe_key,
                        "jorftext_id": jorftext_id,
                        "raw_json": Json(it),
                    }

                    cur.execute(insert_sql, params)
                    if cur.rowcount == 1:
                        inserted += 1
                    else:
                        deduped += 1

                # stop heuristic: if a full page yields zero in-window items, you're likely past date range
                if not any_in_window:
                    stop_reason = "no_items_in_window"
                    break

            conn.commit()

    return {
        "ok": True,
        "source": source,
        "days": days,
        "strict": strict,
        "page_size": page_size,
        "max_pages": max_pages,
        "from": start.isoformat(),
        "to": today.isoformat(),
        "pages_fetched": pages_fetched,
        "seen": seen,
        "kept_after_strict": kept_after_strict,
        "kept_in_window": kept_in_window,
        "inserted": inserted,
        "deduped": deduped,
        "stop_reason": stop_reason,
        "dropped_reasons": dict(dropped_reasons.most_common(10)),
    }
