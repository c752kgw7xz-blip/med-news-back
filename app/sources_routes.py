# app/sources_routes.py
"""
Routes admin pour gérer et tester les sources de collecte.

GET  /admin/sources/status
     État de chaque source : dernière collecte, nb candidats, erreurs

POST /admin/sources/collect/jorf
POST /admin/sources/collect/kali
POST /admin/sources/collect/has
POST /admin/sources/collect/ansm
POST /admin/sources/collect/spf
POST /admin/sources/collect/web       ← scraper HTML (SFH, SFR, SFO, SFPédiatrie, SOFCOT)
POST /admin/sources/collect/all       ← tout en une fois

POST /admin/sources/test-feed?url=…   ← tester un flux RSS manuellement
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from datetime import date, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.db import get_conn
from app.security import require_admin as _require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/sources", tags=["sources"])


# ---------------------------------------------------------------------------
# Anti-SSRF : validation d'URL avant tout fetch externe
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_RANGES = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / métadonnées cloud
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),       # loopback IPv4
    ipaddress.ip_network("::1/128"),           # loopback IPv6
    ipaddress.ip_network("fc00::/7"),          # ULA IPv6
]


def _validate_url(url: str) -> None:
    """Vérifie que l'URL ne pointe pas vers des ressources internes (anti-SSRF)."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="URL invalide")
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise HTTPException(status_code=400, detail="Scheme non autorisé (http/https uniquement)")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname manquant dans l'URL")
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except OSError:
        raise HTTPException(status_code=400, detail="Impossible de résoudre le hostname")
    except Exception:
        raise HTTPException(status_code=400, detail="URL invalide")
    for blocked in _BLOCKED_RANGES:
        if ip in blocked:
            raise HTTPException(
                status_code=400,
                detail="Adresse IP bloquée (réseau privé ou métadonnées cloud)",
            )


# ---------------------------------------------------------------------------
# Statut global de toutes les sources
# ---------------------------------------------------------------------------

@router.get("/status")
def sources_status(request: Request):
    """
    Vue d'ensemble : pour chaque source, combien de candidats
    ont été insérés dans les 35 derniers jours.
    """
    _require_admin(request)

    since = date.today() - timedelta(days=35)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source, status, COUNT(*) as n
                FROM candidates
                WHERE created_at >= %s
                GROUP BY source, status
                ORDER BY source, status;
            """, (since,))
            rows = cur.fetchall()

    # Regrouper par source
    by_source: dict[str, dict] = {}
    for source, status, count in rows:
        if source not in by_source:
            by_source[source] = {"total": 0, "by_status": {}}
        by_source[source]["by_status"][status] = count
        by_source[source]["total"] += count

    # Enrichir avec les métadonnées des sources connues
    known_sources = {
        # PISTE
        "legifrance_jorf":    {"label": "JORF — Journal Officiel",         "type": "piste_api",    "legal": "API officielle PISTE"},
        "piste_kali":         {"label": "KALI — Conventions collectives",  "type": "piste_api",    "legal": "API officielle PISTE"},
        "piste_legi":         {"label": "LEGI — Codes consolidés",         "type": "piste_api",    "legal": "API officielle PISTE"},
        "piste_circulaires":  {"label": "CIRCULAIRES — Ministère santé",   "type": "piste_api",    "legal": "API officielle PISTE"},
        # RSS
        "has_rbp":            {"label": "HAS — Recommandations bonne pratique", "type": "rss",     "legal": "Flux RSS public — Licence Ouverte"},
        "has_ct":             {"label": "HAS — Commission transparence",   "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "has_ap":             {"label": "HAS — Accès précoce",             "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "has_cert":           {"label": "HAS — Certification établissements", "type": "rss",       "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_actu":          {"label": "ANSM — Actualités",               "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_alertes":       {"label": "ANSM — Alertes de sécurité",      "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_decisions":     {"label": "ANSM — Décisions",                "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_ruptures":      {"label": "ANSM — Ruptures d'appro.",        "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "ansm_reco":          {"label": "ANSM — Recommandations",          "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "spf_actu":           {"label": "SPF — Actualités",                "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "spf_publi":          {"label": "SPF — Publications",              "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
        "spf_alertes":        {"label": "SPF — Alertes sanitaires",        "type": "rss",          "legal": "Flux RSS public — Licence Ouverte"},
    }

    result = []
    for src_id, meta in known_sources.items():
        stats = by_source.get(src_id, {"total": 0, "by_status": {}})
        result.append({
            "source_id": src_id,
            **meta,
            "last_35_days": stats,
        })

    return {"ok": True, "since": since.isoformat(), "sources": result}


# ---------------------------------------------------------------------------
# Déclencheurs manuels par source
# ---------------------------------------------------------------------------

@router.post("/collect/jorf")
def collect_jorf(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.scheduler import job_collect_and_analyse
        # On réutilise le bloc JORF du scheduler directement
        from app.piste_routes import (
            _piste_call, _extract_list, _keep_item_with_reason,
            _parse_date10, _official_url,
        )
        from app.collector_utils import build_candidate_row, insert_candidate
        from datetime import timedelta

        source = "legifrance_jorf"
        today = date.today()
        start = today - timedelta(days=days)
        seen = ins = dup = 0

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

        return {"ok": True, "source": "legifrance_jorf", "days": days,
                "seen": seen, "inserted": ins, "deduped": dup}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/kali")
def collect_kali(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.piste_collector import collect_kali as _collect
        return {"ok": True, "source": "piste_kali", **_collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/has")
def collect_has(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_has as _collect
        return {"ok": True, "source": "has", "results": _collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/ansm")
def collect_ansm(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_ansm as _collect
        return {"ok": True, "source": "ansm", "results": _collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/spf")
def collect_spf(request: Request, days: int = Query(default=35, ge=1, le=365)):
    _require_admin(request)
    try:
        from app.rss_collector import collect_spf as _collect
        return {"ok": True, "source": "spf", "results": _collect(days=days)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/web")
def collect_web(request: Request):
    """
    Lance le scraping HTML des sociétés savantes sans flux RSS :
    SFH (hématologie), SFR (radiologie), SFO (ophtalmologie),
    SFPédiatrie, SOFCOT (orthopédie).
    Volume faible — pas de paramètre days (pas de date sur les pages).
    """
    _require_admin(request)
    try:
        from app.web_scraper import scrape_all_web
        results = scrape_all_web()
        total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
        total_errors = sum(1 for r in results.values() if isinstance(r, dict) and "error" in r)
        return {
            "ok": True,
            "total_inserted": total_inserted,
            "total_errors": total_errors,
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/innovation")
def collect_innovation(request: Request, days: int = Query(default=90, ge=1, le=365)):
    """
    Collecte les sources innovation + réglementation dispositifs médicaux :
    - Presse médicale : Vascular Specialist, Vascular News, TCTMD,
      Le Quotidien du Médecin, Egora
    - PubMed (JVS, EJVES, JET, Annals — RCTs & méta-analyses uniquement)
    - Flux RSS journaux : JAMA/NEJM/Lancet/BMJ/Nature Medicine
    - Approbations FDA (PMA Class III + clearances 510k)
    - Dispositifs CE EUDAMED (classes III, codes EMDN vasculaires E06/E07)
    - ANSM sécurité dispositifs médicaux (ansm_securite_dm) — alertes matériovigilance,
      rappels d'implants vasculaires, DHPC sur dispositifs chirurgicaux
    days=90 par défaut pour l'historique récent au premier run.
    """
    _require_admin(request)
    try:
        from app.pubmed_collector import collect_all_pubmed
        from app.rss_collector import collect_feed, FEEDS
        from app.sources_innovation import ALL_INNOVATION_FEEDS
        from app.sources_presse_medicale import ALL_PRESSE_MEDICALE_FEEDS
        from app.fda_collector import collect_all_fda
        from app.eudamed_collector import collect_eudamed_devices

        pubmed_results = collect_all_pubmed(days=days)
        fda_results = collect_all_fda(days=days)
        eudamed_result = {"eudamed": collect_eudamed_devices(days=days)}

        rss_journals: dict = {}
        for feed in ALL_INNOVATION_FEEDS:
            try:
                rss_journals[feed["source"]] = collect_feed(feed, days=days)
            except Exception as e:
                rss_journals[feed["source"]] = {"error": str(e)}

        rss_presse: dict = {}
        for feed in ALL_PRESSE_MEDICALE_FEEDS:
            try:
                rss_presse[feed["source"]] = collect_feed(feed, days=days)
            except Exception as e:
                rss_presse[feed["source"]] = {"error": str(e)}

        # ANSM sécurité DM — alertes matériovigilance sur implants et dispositifs chirurgicaux
        # Inclus ici car les alertes sur endoprothèses/stents/ballons sont réglementaires
        # et doivent apparaître dans la newsletter vasculaire même lors d'un run "innovation".
        _ANSM_DM_SOURCES = {"ansm_securite_dm", "ansm_securite"}
        rss_reglementaire: dict = {}
        for feed in FEEDS:
            if feed["source"] in _ANSM_DM_SOURCES:
                try:
                    rss_reglementaire[feed["source"]] = collect_feed(feed, days=days)
                except Exception as e:
                    rss_reglementaire[feed["source"]] = {"error": str(e)}

        total_inserted = sum(
            r.get("inserted", 0)
            for r in (
                list(pubmed_results.values())
                + list(fda_results.values())
                + list(eudamed_result.values())
                + list(rss_journals.values())
                + list(rss_presse.values())
                + list(rss_reglementaire.values())
            )
            if isinstance(r, dict)
        )
        return {
            "ok": True,
            "days": days,
            "total_inserted": total_inserted,
            "presse_medicale": rss_presse,
            "pubmed": pubmed_results,
            "fda": fda_results,
            "eudamed": eudamed_result,
            "rss_journaux": rss_journals,
            "reglementaire_dm": rss_reglementaire,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect innovation")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/fda")
def collect_fda(request: Request, days: int = Query(default=90, ge=1, le=365)):
    """
    Collecte les approbations FDA de dispositifs vasculaires :
    - PMA (Class III) : endoprothèses, greffons aortiques, filtres cave
    - 510(k) (Class II) : cathéters, stents périphériques, systèmes de délivrance
    Source : open.fda.gov (API publique, pas de clé requise).
    """
    _require_admin(request)
    try:
        from app.fda_collector import collect_all_fda
        results = collect_all_fda(days=days)
        total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
        return {
            "ok": True,
            "days": days,
            "total_inserted": total_inserted,
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect fda")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/eudamed")
def collect_eudamed(request: Request, days: int = Query(default=90, ge=1, le=365)):
    """
    Collecte les dispositifs CE marqués dans EUDAMED (base UE).
    Filtre : Classe III (Im), codes EMDN vasculaires E06/E07 (prothèses vasculaires,
    stents périphériques), + mots-clés vasculaires côté client.
    Source : https://ec.europa.eu/tools/eudamed/ (API publique).
    """
    _require_admin(request)
    try:
        from app.eudamed_collector import collect_eudamed_devices
        result = collect_eudamed_devices(days=days)
        return {
            "ok": True,
            "days": days,
            **result,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur collect eudamed")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/enrich/pubmed-abstracts")
def enrich_pubmed_abstracts(request: Request):
    """
    Re-fetche les abstracts PubMed pour les candidats en DB sans content_raw.

    Cas d'usage : après un run de collecte où NCBI a renvoyé des timeouts ou
    des rate-limits, certains articles ont été insérés sans abstract.
    Cette route les retrouve et les enrichit via l'API NCBI efetch.

    Ne touche pas aux candidats déjà traités (LLM_DONE, APPROVED, REJECTED).
    """
    _require_admin(request)
    try:
        from app.pubmed_collector import enrich_empty_abstracts
        stats = enrich_empty_abstracts()
        return {"ok": True, **stats}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur enrich pubmed-abstracts")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/enrich/unpaywall")
def enrich_unpaywall(
    request: Request,
    limit: int = Query(default=200, ge=1, le=500, description="Nombre max de candidats à enrichir"),
):
    """
    Enrichit le content_raw des candidats PubMed via Unpaywall + Europe PMC.

    Pour chaque candidat pubmed_* avec un DOI mais un abstract court (< 1 200 chars),
    tente de récupérer le full text en open access :
      1. Unpaywall (api.unpaywall.org) → URL OA légale
      2. Europe PMC (fullTextXML) → texte complet parsé depuis JATS XML
      3. Fallback HTML : page auteur / preprint si disponible

    Content_raw n'est mis à jour que si le full text apporte au moins 2× plus de contenu
    que l'abstract actuel.

    Typiquement : ~35 % des RCTs sont en open access via PMC (mandats NIH/EU).
    """
    _require_admin(request)
    try:
        from app.unpaywall_client import enrich_with_unpaywall
        stats = enrich_with_unpaywall(limit=limit)
        return {"ok": True, **stats}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur enrich unpaywall")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/all")
def collect_all(request: Request, days: int = Query(default=35, ge=1, le=365)):
    """Lance la collecte complète de toutes les sources."""
    _require_admin(request)
    try:
        from app.piste_collector import collect_all_piste_fonds
        from app.rss_collector import collect_all_rss
        from app.pubmed_collector import collect_all_pubmed
        return {
            "ok": True,
            "days": days,
            "piste_extra": collect_all_piste_fonds(days=days),
            "rss": collect_all_rss(days=days),
            "pubmed": collect_all_pubmed(days=days),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


@router.post("/collect/pratique")
def collect_pratique(request: Request, days: int = Query(default=90, ge=1, le=365)):
    """
    Collecte uniquement les sources pratiques médicales :
    recommandations HAS, bon usage ANSM, sociétés savantes, académie de médecine.
    days=90 par défaut pour capturer l'historique récent lors du premier run.
    """
    _require_admin(request)
    try:
        from app.rss_collector import collect_pratique as _collect
        results = _collect(days=days)
        total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
        total_errors = sum(r.get("errors", 0) for r in results.values() if isinstance(r, dict))
        return {
            "ok": True,
            "days": days,
            "total_inserted": total_inserted,
            "total_errors": total_errors,
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")


# ---------------------------------------------------------------------------
# Test d'un flux RSS arbitraire
# ---------------------------------------------------------------------------

@router.post("/test-feed")
def test_rss_feed(
    request: Request,
    url: str = Query(..., description="URL du flux RSS à tester"),
):
    """
    Teste un flux RSS : retourne les 5 premières entrées sans rien insérer en base.
    Utile pour vérifier qu'un nouveau flux est lisible avant de l'activer.
    """
    _require_admin(request)

    _validate_url(url)

    try:
        from app.rss_collector import fetch_feed, _entry_title, _parse_entry_date, _entry_url

        parsed = fetch_feed(url)
        if parsed is None:
            return {"ok": False, "error": "Impossible de récupérer le flux"}

        entries = (parsed.entries or [])[:5]
        sample = []
        for e in entries:
            sample.append({
                "title": _entry_title(e),
                "url": _entry_url(e),
                "date": str(_parse_entry_date(e)),
            })

        feed_meta = {}
        if hasattr(parsed, "feed"):
            feed_meta = {
                "title": getattr(parsed.feed, "title", ""),
                "description": getattr(parsed.feed, "description", ""),
                "link": getattr(parsed.feed, "link", ""),
            }

        return {
            "ok": True,
            "feed": feed_meta,
            "total_entries": len(parsed.entries or []),
            "sample": sample,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Erreur sources admin")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:200]}")
