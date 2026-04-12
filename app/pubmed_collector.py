# app/pubmed_collector.py
"""
Collecteur PubMed via NCBI E-utilities.

Utilisé pour les journaux dont le RSS Elsevier/SAGE a été supprimé (410 Gone),
notamment en chirurgie vasculaire : JVS, EJVES, JET, Annals of Vascular Surgery.

API : https://eutils.ncbi.nlm.nih.gov/entrez/eutils/
  - esearch.fcgi : recherche par journal + date → liste de PMIDs
  - efetch.fcgi  : récupération détails XML par lot de PMIDs (titres, abstracts, dates)

Rate limit NCBI :
  - Sans clé  : 3 req/s
  - Avec clé  : 10 req/s (NCBI_API_KEY dans l'env)
  Stratégie : batch de 20 PMIDs par efetch + sleep entre lots si nécessaire.

Sources configurées (voir PUBMED_SOURCES) :
  pubmed_jvs           : Journal of Vascular Surgery
  pubmed_ejves         : European Journal of Vascular and Endovascular Surgery
  pubmed_jet           : Journal of Endovascular Therapy
  pubmed_ann_vasc_surg : Annals of Vascular Surgery
"""

from __future__ import annotations

import logging
import os
import time
import xml.etree.ElementTree as ET
from datetime import date, timedelta
from typing import Any

import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn

logger = logging.getLogger(__name__)

NCBI_BASE = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils"
NCBI_API_KEY = os.getenv("NCBI_API_KEY", "")

# ---------------------------------------------------------------------------
# Sources PubMed — journaux dont le RSS éditeur est mort (Elsevier 410 Gone)
# ---------------------------------------------------------------------------

PUBMED_SOURCES: list[dict] = [

    # ── Journal of Vascular Surgery (JVS) ────────────────────────────────
    # THE référence en chirurgie vasculaire ouverte + endovasculaire.
    # Essais cliniques (EVAR vs ouvert, stenting carotide, AOMI, AAA),
    # résultats à long terme, nouvelles techniques (FEVAR, TEVAR hybride).
    # PubMed : ~250 articles/an. Filtre LLM min_score=5 recommandé.
    {
        "source": "pubmed_jvs",
        "journal_term": '"J Vasc Surg"[Journal]',
        "label": "Journal of Vascular Surgery (JVS)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 5,
    },

    # ── European Journal of Vascular and Endovascular Surgery (EJVES) ────
    # Organe officiel de l'ESVS. Guidelines ESVS (AAA, sténose carotide,
    # AOMI, ischémie aiguë, anévrisme poplité, traumatismes vasculaires).
    # Haut ratio recommandation/étude → pertinence pratique élevée.
    {
        "source": "pubmed_ejves",
        "journal_term": '"Eur J Vasc Endovasc Surg"[Journal]',
        "label": "European Journal of Vascular and Endovascular Surgery (EJVES/ESVS)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 5,
    },

    # ── Journal of Endovascular Therapy (JET) ─────────────────────────────
    # Spécialisé techniques endovasculaires : EVAR, TEVAR, FEVAR,
    # chimney/sandwich, drug-coated balloons, stenting carotide (CAS/TCAR).
    # Couvre aussi les accès vasculaires et la dialyse.
    {
        "source": "pubmed_jet",
        "journal_term": '"J Endovasc Ther"[Journal]',
        "label": "Journal of Endovascular Therapy (JET)",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 5,
    },

    # ── Annals of Vascular Surgery ────────────────────────────────────────
    # Fondé à Paris (Annales de Chirurgie Vasculaire) — forte présence
    # chirurgie française et européenne. Techniques opératoires, complications,
    # résultats à moyen terme. Utile pour pratique quotidienne.
    {
        "source": "pubmed_ann_vasc_surg",
        "journal_term": '"Ann Vasc Surg"[Journal]',
        "label": "Annals of Vascular Surgery",
        "source_type": "innovation",
        "specialty_hint": "chirurgie-vasculaire",
        "min_score_hint": 4,
    },
]


# ---------------------------------------------------------------------------
# Helpers NCBI E-utilities
# ---------------------------------------------------------------------------

def _ncbi_params(extra: dict) -> dict:
    """Paramètres de base pour toutes les requêtes NCBI."""
    p: dict = {"db": "pubmed", "retmode": "json", "tool": "med-news-back", "email": "contact@mednews.fr"}
    if NCBI_API_KEY:
        p["api_key"] = NCBI_API_KEY
    p.update(extra)
    return p


def _search_pmids(journal_term: str, days: int, client: httpx.Client) -> list[str]:
    """
    Recherche les PMIDs publiés dans [today-days, today] pour un journal donné.
    Retourne au max 200 PMIDs (suffisant pour un run mensuel).
    """
    since = (date.today() - timedelta(days=days)).strftime("%Y/%m/%d")
    today = date.today().strftime("%Y/%m/%d")
    term = f'{journal_term} AND ("{since}"[PDAT] : "{today}"[PDAT])'
    params = _ncbi_params({
        "term": term,
        "retmax": 200,
        "sort": "date",
    })
    try:
        r = client.get(f"{NCBI_BASE}/esearch.fcgi", params=params, timeout=15)
        r.raise_for_status()
        data = r.json()
        return data.get("esearchresult", {}).get("idlist", [])
    except Exception as e:
        logger.warning("[pubmed] esearch error for %s: %s", journal_term, e)
        return []


def _fetch_articles(pmids: list[str], client: httpx.Client) -> list[dict]:
    """
    Récupère les détails (titre, abstract, date, DOI) pour une liste de PMIDs.
    Traitement par lots de 20 pour respecter les limites NCBI.
    """
    articles = []
    batch_size = 20
    for i in range(0, len(pmids), batch_size):
        batch = pmids[i : i + batch_size]
        params = _ncbi_params({
            "id": ",".join(batch),
            "rettype": "abstract",
            "retmode": "xml",
        })
        # Supprimer retmode=json (déjà en xml)
        params["retmode"] = "xml"
        try:
            r = client.get(f"{NCBI_BASE}/efetch.fcgi", params=params, timeout=20)
            r.raise_for_status()
            articles.extend(_parse_efetch_xml(r.text))
        except Exception as e:
            logger.warning("[pubmed] efetch error for batch %s: %s", batch[:3], e)
        # Rate limit : 3 req/s sans clé, 10 req/s avec clé
        time.sleep(0.35 if NCBI_API_KEY else 0.4)
    return articles


def _parse_efetch_xml(xml_text: str) -> list[dict]:
    """Parse le XML efetch → liste de dicts avec les champs utiles."""
    results = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.warning("[pubmed] XML parse error: %s", e)
        return []

    for article in root.findall(".//PubmedArticle"):
        try:
            medline = article.find("MedlineCitation")
            if medline is None:
                continue

            pmid_el = medline.find("PMID")
            pmid = pmid_el.text.strip() if pmid_el is not None else None
            if not pmid:
                continue

            art = medline.find("Article")
            if art is None:
                continue

            # Titre
            title_el = art.find("ArticleTitle")
            title = "".join(title_el.itertext()).strip() if title_el is not None else ""

            # Abstract
            abstract_parts = []
            for ab in art.findall(".//AbstractText"):
                label = ab.get("Label")
                text = "".join(ab.itertext()).strip()
                if text:
                    abstract_parts.append(f"{label}: {text}" if label else text)
            abstract = "\n".join(abstract_parts)

            # Date de publication
            pub_date = _extract_pub_date(art, medline)

            # DOI
            doi = None
            for id_el in article.findall(".//ArticleId"):
                if id_el.get("IdType") == "doi":
                    doi = id_el.text.strip() if id_el.text else None
                    break

            # Journal
            journal_el = art.find("Journal/Title")
            journal = journal_el.text.strip() if journal_el is not None else ""

            results.append({
                "pmid": pmid,
                "title": title,
                "abstract": abstract,
                "pub_date": pub_date,
                "doi": doi,
                "journal": journal,
            })
        except Exception as e:
            logger.debug("[pubmed] article parse error: %s", e)
            continue

    return results


def _extract_pub_date(art_el: ET.Element, medline_el: ET.Element) -> date:
    """Extrait la date de publication de l'article (ArticleDate > PubDate > today)."""
    # ArticleDate (electronic pub date — la plus précise)
    for ad in art_el.findall("ArticleDate"):
        try:
            y = int(ad.findtext("Year", "0"))
            m = int(ad.findtext("Month", "1"))
            d = int(ad.findtext("Day", "1"))
            if y > 2000:
                return date(y, m, d)
        except (ValueError, TypeError):
            pass

    # PubDate (dans Journal/JournalIssue)
    for pd in art_el.findall(".//PubDate"):
        try:
            y = int(pd.findtext("Year", "0"))
            m_raw = pd.findtext("Month", "1")
            m = _month_str_to_int(m_raw)
            d = int(pd.findtext("Day", "1"))
            if y > 2000:
                return date(y, m, d)
        except (ValueError, TypeError):
            pass

    # MedlineDate fallback (ex: "2026 Jan-Feb")
    ml_date = art_el.findtext(".//MedlineDate", "")
    if ml_date:
        parts = ml_date.split()
        try:
            y = int(parts[0])
            m = _month_str_to_int(parts[1][:3]) if len(parts) > 1 else 1
            return date(y, m, 1)
        except (ValueError, IndexError):
            pass

    return date.today()


_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

def _month_str_to_int(s: str) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return _MONTH_MAP.get((s or "").lower()[:3], 1)


# ---------------------------------------------------------------------------
# Collecteur principal
# ---------------------------------------------------------------------------

def collect_pubmed_source(source_cfg: dict, days: int = 90) -> dict[str, int]:
    """
    Collecte les articles PubMed pour une source donnée et les insère en base.

    Returns:
        {"fetched": N, "inserted": N, "skipped": N, "errors": N}
    """
    src = source_cfg["source"]
    journal_term = source_cfg["journal_term"]
    specialty_hint = source_cfg.get("specialty_hint", "")
    source_type = source_cfg.get("source_type", "innovation")

    stats = {"fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}

    with httpx.Client(follow_redirects=True) as client:
        pmids = _search_pmids(journal_term, days=days, client=client)
        if not pmids:
            logger.info("[pubmed/%s] no PMIDs found for last %d days", src, days)
            return stats

        stats["fetched"] = len(pmids)
        logger.info("[pubmed/%s] %d PMIDs found", src, len(pmids))

        articles = _fetch_articles(pmids, client=client)

    with get_conn() as conn:
        with conn.cursor() as cur:
            for art in articles:
                try:
                    pmid = art["pmid"]
                    pub_date = art["pub_date"]
                    title = art["title"] or "(sans titre)"
                    abstract = art.get("abstract") or ""
                    doi = art.get("doi")
                    official_url = f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/"

                    raw_payload = {
                        "pmid": pmid,
                        "title": title,
                        "abstract": abstract,
                        "journal": art.get("journal", ""),
                        "pub_date": str(pub_date),
                        "doi": doi,
                        "source": src,
                        "source_type": source_type,
                        "specialty_hint": specialty_hint,
                    }

                    row = build_candidate_row(
                        source=src,
                        external_id=pmid,
                        official_url=official_url,
                        official_date=pub_date,
                        title_raw=title,
                        content_raw=abstract if abstract else None,
                        raw_payload=raw_payload,
                    )

                    inserted = insert_candidate(cur, row)
                    if inserted:
                        stats["inserted"] += 1
                    else:
                        stats["skipped"] += 1

                except Exception as e:
                    logger.warning("[pubmed/%s] insert error for pmid %s: %s", src, art.get("pmid"), e)
                    stats["errors"] += 1

        conn.commit()

    logger.info("[pubmed/%s] done — %s", src, stats)
    return stats


def collect_all_pubmed(days: int = 90) -> dict[str, dict]:
    """Collecte toutes les sources PubMed configurées."""
    results = {}
    for source_cfg in PUBMED_SOURCES:
        src = source_cfg["source"]
        try:
            results[src] = collect_pubmed_source(source_cfg, days=days)
        except Exception as e:
            logger.error("[pubmed/%s] erreur: %s", src, e)
            results[src] = {"error": str(e)}
    return results
