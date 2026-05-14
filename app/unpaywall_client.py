# app/unpaywall_client.py
"""
Enrichissement full text via Unpaywall + Europe PMC.

Problème résolu :
  Les candidats PubMed n'ont que l'abstract (300 mots) en content_raw.
  Le LLM ne peut pas vérifier les effectifs exacts, les IC95%, les sous-groupes,
  les conflits d'intérêts — éléments décisifs pour "est-ce que ça change la pratique ?".

Solution :
  1. Unpaywall (api.unpaywall.org) : pour chaque DOI, retourne l'URL légale du
     full text si disponible. ~35% des RCTs sont en open access via PMC (mandats NIH/EU).
  2. Europe PMC (europepmc.org/api) : pour les articles indexés dans PMC, retourne
     le full text en XML propre (abstract + corps + méthodes + résultats + discussion).

Pipeline d'enrichissement :
  candidates (pubmed_*, status NEW/LLM_FAILED, doi présent)
    → Unpaywall → PMC ID ou URL OA
      → Europe PMC full text XML → extraction texte pur
        → UPDATE content_raw (si enrichissement > abstract seul)

API Unpaywall :
  GET https://api.unpaywall.org/v2/{doi}?email=contact@med-news.fr
  Gratuit, pas de clé. Rate limit : 100 000 req/jour.
  Champs utilisés : is_oa, best_oa_location.url, pmcid.

API Europe PMC :
  GET https://www.ebi.ac.uk/europepmc/webservices/rest/{pmid}/fullTextXML
  Gratuit, pas de clé. Retourne l'article complet en JATS XML.

Légalité :
  Unpaywall référence uniquement des versions légalement accessibles (PMC, preprints,
  pages auteurs). Le full text PMC est sous licence permissive (CC-BY ou PMC OA).
  Ce collecteur ne reproduit pas le contenu — il l'utilise en interne pour le scoring LLM.
"""

from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from typing import Any

import httpx

from app.db import get_conn

logger = logging.getLogger(__name__)

UNPAYWALL_EMAIL = "contact@med-news.fr"
UNPAYWALL_BASE  = "https://api.unpaywall.org/v2"
EUROPEPMC_BASE  = "https://www.ebi.ac.uk/europepmc/webservices/rest"

# Seuil : on n'écrase content_raw que si le full text apporte au moins 2x plus de contenu
_MIN_FULLTEXT_CHARS = 1500
_MAX_FULLTEXT_CHARS = 12_000   # tronqué — le LLM n'a besoin que des 3000 premiers chars


# ---------------------------------------------------------------------------
# Unpaywall : trouver l'URL ou le PMC ID du full text
# ---------------------------------------------------------------------------

def _query_unpaywall(doi: str, client: httpx.Client) -> dict | None:
    """
    Requête Unpaywall pour un DOI.
    Retourne le dict JSON brut ou None en cas d'erreur.
    """
    try:
        r = client.get(
            f"{UNPAYWALL_BASE}/{doi}",
            params={"email": UNPAYWALL_EMAIL},
            timeout=10,
        )
        if r.status_code == 404:
            return None   # DOI inconnu d'Unpaywall
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug("[unpaywall] %s : %s", doi, e)
        return None


def _extract_oa_info(data: dict) -> dict | None:
    """
    Extrait les informations utiles depuis le JSON Unpaywall.
    Retourne None si l'article n'est pas en open access.
    """
    if not data.get("is_oa"):
        return None

    # PMC ID direct (le plus fiable pour Europe PMC)
    pmcid: str | None = None
    for loc in data.get("oa_locations", []):
        url = loc.get("url", "")
        if "pmc/articles/PMC" in url or "europepmc.org" in url:
            # Extraire PMC ID depuis l'URL
            import re
            m = re.search(r"PMC(\d+)", url)
            if m:
                pmcid = f"PMC{m.group(1)}"
                break

    best = data.get("best_oa_location") or {}
    oa_url: str | None = best.get("url") or best.get("url_for_landing_page")
    oa_pdf: str | None = best.get("url_for_pdf")
    license_: str | None = best.get("license")

    return {
        "pmcid":   pmcid,
        "oa_url":  oa_url,
        "oa_pdf":  oa_pdf,
        "license": license_,
        "oa_status": data.get("oa_status"),
    }


# ---------------------------------------------------------------------------
# Europe PMC : récupérer le full text XML
# ---------------------------------------------------------------------------

def _fetch_europepmc_fulltext(pmid: str, client: httpx.Client) -> str | None:
    """
    Récupère le full text JATS XML depuis Europe PMC pour un PMID.
    Retourne le texte extrait (sections utiles) ou None.
    """
    try:
        r = client.get(
            f"{EUROPEPMC_BASE}/{pmid}/fullTextXML",
            timeout=20,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return _parse_jats_xml(r.text)
    except Exception as e:
        logger.debug("[europepmc] pmid=%s : %s", pmid, e)
        return None


def _parse_jats_xml(xml_text: str) -> str | None:
    """
    Extrait les sections utiles d'un article JATS XML :
    Abstract, Methods, Results, Discussion, Conclusion.
    Retourne le texte brut concaténé, tronqué à _MAX_FULLTEXT_CHARS.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    sections_wanted = {
        "abstract", "intro", "introduction",
        "methods", "results", "discussion", "conclusion",
        "sec",  # sections génériques
    }

    parts: list[str] = []

    # Abstract structuré
    for ab in root.findall(".//{http://jats.nlm.nih.gov}abstract") or root.findall(".//abstract"):
        text = "".join(ab.itertext()).strip()
        if text:
            parts.append(f"[ABSTRACT]\n{text}")

    # Corps de l'article par section
    for sec in root.findall(".//{http://jats.nlm.nih.gov}sec") or root.findall(".//sec"):
        title_el = sec.find("{http://jats.nlm.nih.gov}title") or sec.find("title")
        title = (title_el.text or "").lower().strip() if title_el is not None else ""
        if any(kw in title for kw in ("method", "result", "discuss", "conclusion", "background", "finding")):
            text = "".join(sec.itertext()).strip()
            if text and len(text) > 100:
                parts.append(f"[{title.upper()}]\n{text[:3000]}")

    if not parts:
        # Fallback : tout le texte brut
        full = "".join(root.itertext()).strip()
        if full:
            parts.append(full[:_MAX_FULLTEXT_CHARS])

    result = "\n\n".join(parts)
    return result[:_MAX_FULLTEXT_CHARS] if result else None


# ---------------------------------------------------------------------------
# Enrichissement via URL OA générique (HTML)
# ---------------------------------------------------------------------------

def _fetch_oa_url_text(url: str, client: httpx.Client) -> str | None:
    """
    Fetch une URL OA (page auteur, preprint serveur, PMC HTML)
    et extrait le texte brut. Fallback si Europe PMC n'a pas l'article.
    """
    # Éviter les PDFs — trop complexes à parser
    if url.lower().endswith(".pdf") or "/pdf" in url.lower():
        return None
    # Éviter les pages paywallées connues
    skip_domains = {"elsevier.com", "springer.com", "wiley.com", "nejm.org", "jama.com"}
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower()
    if any(d in domain for d in skip_domains):
        return None

    try:
        r = client.get(
            url,
            headers={"User-Agent": "MedNewsBot/1.0 (veille; contact@med-news.fr)"},
            follow_redirects=True,
            timeout=15,
        )
        if r.status_code != 200:
            return None
        # Extraction texte naïve : retire les balises HTML
        from html.parser import HTMLParser

        class _TextExtractor(HTMLParser):
            def __init__(self):
                super().__init__()
                self.parts: list[str] = []
                self._skip = False

            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style", "nav", "footer", "header"):
                    self._skip = True

            def handle_endtag(self, tag):
                if tag in ("script", "style", "nav", "footer", "header"):
                    self._skip = False

            def handle_data(self, data):
                if not self._skip:
                    stripped = data.strip()
                    if stripped:
                        self.parts.append(stripped)

        extractor = _TextExtractor()
        extractor.feed(r.text)
        text = " ".join(extractor.parts)
        return text[:_MAX_FULLTEXT_CHARS] if len(text) > _MIN_FULLTEXT_CHARS else None

    except Exception as e:
        logger.debug("[oa_url] %s : %s", url, e)
        return None


# ---------------------------------------------------------------------------
# Enrichissement principal
# ---------------------------------------------------------------------------

def enrich_with_unpaywall(
    limit: int = 200,
    sources: list[str] | None = None,
) -> dict[str, int]:
    """
    Enrichit content_raw des candidats PubMed via Unpaywall + Europe PMC.

    Args:
        limit   : nombre maximum de candidats à traiter par appel
        sources : liste de sources à enrichir (défaut : toutes pubmed_*)

    Returns:
        {"checked": N, "enriched": N, "oa_not_found": N, "errors": N}
    """
    stats = {"checked": 0, "enriched": 0, "oa_not_found": 0, "errors": 0}

    # Requête des candidats avec DOI et contenu court (abstract seul ou vide)
    source_filter = sources or []
    with get_conn() as conn:
        with conn.cursor() as cur:
            if source_filter:
                source_clause = "AND source = ANY(%s)"
                params: tuple = (limit, source_filter)
            else:
                source_clause = "AND source LIKE 'pubmed_%'"
                params = (limit,)

            cur.execute(f"""
                SELECT id,
                       raw_json->>'doi'  AS doi,
                       raw_json->>'pmid' AS pmid,
                       COALESCE(content_raw, '') AS current_content
                FROM candidates
                WHERE status IN ('NEW', 'LLM_FAILED')
                  {source_clause}
                  AND raw_json->>'doi' IS NOT NULL
                  AND (
                    content_raw IS NULL
                    OR TRIM(content_raw) = ''
                    OR LENGTH(content_raw) < %s
                  )
                ORDER BY official_date DESC
                LIMIT %s
            """,
            (*(source_filter if source_filter else []),
             1200,   # abstract court = probablement tronqué
             limit,))

            rows = cur.fetchall()

    if not rows:
        logger.info("[unpaywall] aucun candidat à enrichir")
        return stats

    logger.info("[unpaywall] %d candidats à traiter", len(rows))

    with httpx.Client(follow_redirects=True) as client:
        with get_conn() as conn:
            with conn.cursor() as cur:
                for row in rows:
                    cand_id, doi, pmid, current_content = row
                    stats["checked"] += 1

                    try:
                        fulltext = _enrich_one(doi, pmid, current_content, client)

                        if fulltext:
                            cur.execute(
                                "UPDATE candidates SET content_raw = %s WHERE id = %s",
                                (fulltext, cand_id),
                            )
                            stats["enriched"] += 1
                            logger.debug("[unpaywall] enrichi id=%s doi=%s (%d chars)",
                                         cand_id, doi, len(fulltext))
                        else:
                            stats["oa_not_found"] += 1

                    except Exception as e:
                        logger.warning("[unpaywall] id=%s doi=%s : %s", cand_id, doi, e)
                        stats["errors"] += 1

                    # Rate limit conservatif
                    time.sleep(0.5)

            conn.commit()

    logger.info("[unpaywall] terminé — %s", stats)
    return stats


def _enrich_one(
    doi: str | None,
    pmid: str | None,
    current_content: str,
    client: httpx.Client,
) -> str | None:
    """
    Tentative d'enrichissement pour un article.
    Retourne le full text si trouvé et meilleur que l'actuel, sinon None.
    """
    if not doi:
        return None

    # 1. Chercher via Unpaywall
    data = _query_unpaywall(doi, client)
    if not data:
        return None

    oa_info = _extract_oa_info(data)
    if not oa_info:
        return None

    fulltext: str | None = None

    # 2. Essayer Europe PMC avec le PMID (le plus propre)
    if pmid:
        fulltext = _fetch_europepmc_fulltext(pmid, client)
        time.sleep(0.3)

    # 3. Fallback : URL OA générique (PMC HTML, preprint, page auteur)
    if not fulltext and oa_info.get("oa_url"):
        fulltext = _fetch_oa_url_text(oa_info["oa_url"], client)

    if not fulltext or len(fulltext) < _MIN_FULLTEXT_CHARS:
        return None

    # N'enrichir que si on apporte significativement plus que l'abstract actuel
    if len(fulltext) <= len(current_content) * 1.5:
        return None

    return fulltext
