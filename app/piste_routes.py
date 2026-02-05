# app/piste_routes.py
from __future__ import annotations

import os
from datetime import date, timedelta
from typing import Any

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
# Safe PISTE call wrapper (surface real errors)
# ----------------------
def _piste_call(path: str, payload: dict[str, Any]) -> Any:
    if piste_post is None:
        raise HTTPException(status_code=501, detail="piste_post not installed")

    try:
        return piste_post(path, payload)
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
        if isinstance(v, str) and len(v) >= 10:
            try:
                return date.fromisoformat(v[:10])
            except Exception:
                pass

    for k, v in detail.items():
        if "date" in k.lower() and isinstance(v, str) and len(v) >= 10:
            try:
                return date.fromisoformat(v[:10])
            except Exception:
                continue

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


def _keep_item(nature: Any, title: Any) -> bool:
    n = (nature or "").strip()
    t = (title or "").strip().lower()

    if n in DROP_NATURE:
        return False
    if KEEP_NATURE and n not in KEEP_NATURE:
        return False
    for bad in DROP_TITLE_CONTAINS:
        if bad in t:
            return False
    return True


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

    date_fields = {k: v for k, v in detail.items() if "date" in k.lower()}

    return {
        "ok": True,
        "sample_container_id": cont_ids[0],
        "sample_text_id": tid,
        "title": _title(detail),
        "parsed_pub_date": (_parse_pub_date(detail).isoformat() if _parse_pub_date(detail) else None),
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
):
    """
    READ-ONLY. Sandbox-friendly.
    IMPORTANT: /search requires a nested "recherche" object (per official DILA examples).
    Normalisation adapted to actual /search response: IDs/titles are often under titles[0].
    Includes an anti-noise filter for JORF items.
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
    for it in items:
        if not isinstance(it, dict):
            continue

        titles = it.get("titles") if isinstance(it.get("titles"), list) else []
        t0 = titles[0] if titles and isinstance(titles[0], dict) else {}

        jorftext_id = t0.get("cid")  # typically "JORFTEXT..."
        title = t0.get("title")

        nature = it.get("nature") or it.get("type")

        if not _keep_item(nature, title):
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
        "pageNumber": page_number,
        "pageSize": page_size,
        "count": len(results),
        "results": results,
        "raw_keys": sorted(list(data.keys())),
    }


@router.post("/jorf/search-debug")
def jorf_search_debug(request: Request):
    """
    READ-ONLY debug endpoint for /search.
    Uses the minimal valid /search payload (with nested "recherche").
    Returns the first item raw to adapt parsing if needed.
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
