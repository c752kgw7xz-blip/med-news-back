# app/piste_routes.py
from __future__ import annotations

import os
from datetime import date, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request

# Must exist in app/piste_client.py for this to work
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
# Helpers
# ----------------------
def _is_id(v: Any, prefix: str) -> bool:
    return isinstance(v, str) and v.startswith(prefix)


def _pick_container_ids(last_payload: Any) -> list[str]:
    """
    lastNJo returns different shapes depending on versions.
    We extract all JORFCONT... ids robustly.
    """
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
    # dedupe preserving order
    seen = set()
    uniq = []
    for c in out:
        if c not in seen:
            uniq.append(c)
            seen.add(c)
    return uniq


def _pick_text_ids(cont_payload: Any) -> list[str]:
    """
    jorfCont returns list/dict; extract JORFTEXT... ids robustly.
    """
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

    # dedupe preserving order
    seen = set()
    uniq = []
    for t in out:
        if t not in seen:
            uniq.append(t)
            seen.add(t)
    return uniq


def _parse_pub_date(detail: dict[str, Any]) -> date | None:
    """
    Légifrance payloads vary. We try a set of known fields, and as fallback,
    we scan for keys containing 'date' that look like ISO dates.
    """
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

    # fallback: scan any *date* field
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
# Routes (READ-ONLY)
# ----------------------
@router.post("/jorf/last-7-days")
def jorf_last_7_days(
    request: Request,
    nb_jo: int = 50,        # how many JO containers to inspect (not DB)
    page_size: int = 200,   # texts per container page
    limit: int = 200,       # cap response size to avoid huge payloads
):
    """
    READ-ONLY.
    Strategy: lastNJo -> each JORFCONT -> list JORFTEXT -> detail (/consult/jorf) -> filter on date in last 7 days.
    Returns normalized minimal fields.
    """
    _require_admin(request)

    if piste_post is None:
        raise HTTPException(status_code=501, detail="piste_post not installed")

    today = date.today()
    start = today - timedelta(days=7)

    last = piste_post("/consult/lastNJo", {"nbElement": nb_jo})
    cont_ids = _pick_container_ids(last)

    out: list[dict[str, Any]] = []
    errors = 0
    skipped_no_date = 0

    for cont_id in cont_ids:
        if len(out) >= limit:
            break

        cont = piste_post(
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
                detail = piste_post("/consult/jorf", {"highlightActivated": False, "id": tid})
            except Exception:
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
    READ-ONLY debug endpoint:
    - shows what lastNJo returns
    - extracts first container + first text
    - returns the date-related fields seen in /consult/jorf detail
    Useful when last-7-days returns 0.
    """
    _require_admin(request)

    if piste_post is None:
        raise HTTPException(status_code=501, detail="piste_post not installed")

    last = piste_post("/consult/lastNJo", {"nbElement": 5})
    cont_ids = _pick_container_ids(last)

    if not cont_ids:
        return {"ok": True, "note": "no containers extracted", "last_type": str(type(last))}

    cont = piste_post(
        "/consult/jorfCont",
        {"highlightActivated": False, "id": cont_ids[0], "pageNumber": 1, "pageSize": 5},
    )
    text_ids = _pick_text_ids(cont)

    if not text_ids:
        return {"ok": True, "containers": cont_ids, "note": "no text ids extracted from first container"}

    tid = text_ids[0]
    detail = piste_post("/consult/jorf", {"highlightActivated": False, "id": tid})

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
