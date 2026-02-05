from datetime import date, timedelta
from fastapi import APIRouter, HTTPException, Request

from app.piste_client import piste_post  # tu l'as déjà en OPTIONAL dans main

router = APIRouter(prefix="/admin/piste", tags=["piste"])

def _require_admin(request: Request) -> None:
    # on réutilise le header x-admin-secret, mais comme _require_secret est dans main,
    # on fait simple ici (ou tu le déplaces dans un utils).
    import os
    from fastapi import HTTPException
    expected = os.environ.get("ADMIN_SECRET")
    got = request.headers.get("x-admin-secret")
    if not expected or got != expected:
        raise HTTPException(status_code=401, detail="unauthorized")

@router.post("/jorf/last-7-days")
def jorf_last_7_days(request: Request):
    """
    Lecture seule. Ne touche pas la DB.
    Retourne une liste brute (normalisée) de publications JORF des 7 derniers jours.
    """
    _require_admin(request)

    if piste_post is None:
        raise HTTPException(status_code=501, detail="piste_post not installed in this build")

    today = date.today()
    start = today - timedelta(days=7)

    # IMPORTANT: on réutilise l'API que tu utilises déjà : /consult/lastNJo
    # Puis /consult/jorfCont pour extraire les textes, SANS insérer.
    last = piste_post("/consult/lastNJo", {"nbElement": 30})  # on prend 30 JO, on filtrera par date ensuite

    cont_ids = []
    items = []
    if isinstance(last, dict):
        items = last.get("results") or last.get("list") or last.get("jorfConts") or []
    elif isinstance(last, list):
        items = last

    for x in items if isinstance(items, list) else []:
        if isinstance(x, str) and x.startswith("JORFCONT"):
            cont_ids.append(x)
        elif isinstance(x, dict):
            cid = x.get("id") or x.get("jorfContId")
            if isinstance(cid, str) and cid.startswith("JORFCONT"):
                cont_ids.append(cid)

    # Parcours conteneurs -> récupère les IDs JORFTEXT
    out = []
    for cont_id in cont_ids:
        cont = piste_post(
            "/consult/jorfCont",
            {
                "highlightActivated": False,
                "id": cont_id,
                "pageNumber": 1,
                "pageSize": 200,
            },
        )

        cont_items = []
        if isinstance(cont, dict):
            cont_items = cont.get("results") or cont.get("list") or cont.get("texts") or []
        elif isinstance(cont, list):
            cont_items = cont

        text_ids = []
        for it in cont_items if isinstance(cont_items, list) else []:
            if isinstance(it, str) and it.startswith("JORFTEXT"):
                text_ids.append(it)
            elif isinstance(it, dict):
                tid = it.get("id") or it.get("jorfTextId") or it.get("textId")
                if isinstance(tid, str) and tid.startswith("JORFTEXT"):
                    text_ids.append(tid)

        # Pour chaque texte : détail, et on filtre par date sur les 7 derniers jours
        for tid in text_ids:
            detail = piste_post("/consult/jorf", {"highlightActivated": False, "id": tid})

            if not isinstance(detail, dict):
                continue

            # date de publication (selon les champs réellement retournés)
            d = detail.get("datePublication") or detail.get("datePubli") or detail.get("publicationDate")
            pub_date = None
            if isinstance(d, str) and len(d) >= 10:
                try:
                    pub_date = date.fromisoformat(d[:10])
                except Exception:
                    pub_date = None

            if pub_date is None or pub_date < start or pub_date > today:
                continue

            title = detail.get("title") or detail.get("titre") or detail.get("norTitre") or ""
            pdf_url = detail.get("pdfUrl") or detail.get("pdf") or detail.get("pdf_url")

            out.append(
                {
                    "jorftext_id": tid,
                    "date_publication": pub_date.isoformat(),
                    "titre": title,
                    "pdf_url": pdf_url,
                    "official_url": f"https://www.legifrance.gouv.fr/jorf/id/{tid}",
                }
            )

    return {"ok": True, "from": start.isoformat(), "to": today.isoformat(), "count": len(out), "results": out[:200]}
