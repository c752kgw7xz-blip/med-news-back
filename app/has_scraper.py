# app/has_scraper.py
"""
Enrichissement du contenu HAS : extraction du résumé clinique depuis les pages
de recommandations de bonne pratique (RBP).

Problème de base :
  Le flux RSS HAS (p_3081452) ne contient que le titre + un lien.
  La description RSS est vide ou réduite à 1-2 phrases marketing.
  Le contenu clinique actionnable (résumé, messages clés) est sur la page HTML.

Ce module est appelé depuis collect_feed() pour les sources HAS après insertion
du candidat, afin d'enrichir content_raw avec le vrai résumé clinique.

Extraction ciblée :
  1. Résumé (section id="résumé" ou balise avec class "summary")
  2. Messages clés (section "Messages clés" ou liste de puces intro)
  3. Date de validation (présente dans la sidebar)
  4. Type de document (pour confirmer que c'est une RBP finale et non un cadrage)

Anti-bot HAS :
  Le site HAS renvoie parfois une page HTML avec window.location.href avant le
  vrai contenu. Le même mécanisme que fetch_feed() est réutilisé.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9",
}

_JS_REDIRECT_RE = re.compile(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]")

# Types de documents à garder (RBP finales, recommandations vaccinales, RSP finales)
# On exclut les "Notes de cadrage" et "Notes de synthèse" (déjà filtrées au pré-filtre,
# mais on vérifie en double pour la robustesse).
_SCOPING_DOC_RE = re.compile(
    r"(?i)(note\s+de\s+cadrage|note\s+de\s+synth[eè]se|note\s+de\s+probl[eé]matique)",
)


def _fetch_html(url: str, timeout: int = 20) -> str | None:
    """Récupère le HTML d'une page HAS en gérant le redirect JS anti-bot."""
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS) as client:
            r = client.get(url)
            r.raise_for_status()
            ct = r.headers.get("content-type", "")
            if "html" in ct:
                m = _JS_REDIRECT_RE.search(r.text)
                if m:
                    redirect_path = m.group(1)
                    base = str(r.url).split("/", 3)[:3]
                    redirect_url = "/".join(base) + redirect_path
                    logger.debug("HAS scraper redirect: %s → %s", url, redirect_url)
                    r = client.get(redirect_url)
                    r.raise_for_status()
            return r.text
    except Exception as e:
        logger.warning("HAS scraper fetch failed %s : %s", url, e)
        return None


def _extract_text_block(soup: BeautifulSoup, heading_re: re.Pattern) -> str:
    """
    Trouve une section par son titre (h2/h3/h4 correspondant à heading_re),
    puis collecte tout le texte jusqu'au prochain heading de même niveau.
    """
    for heading in soup.find_all(["h2", "h3", "h4"]):
        if heading_re.search(heading.get_text()):
            parts: list[str] = []
            for sibling in heading.find_next_siblings():
                if sibling.name in ("h2", "h3", "h4"):
                    break
                text = sibling.get_text(" ", strip=True)
                if text:
                    parts.append(text)
            if parts:
                return " ".join(parts)[:3000]
    return ""


_RESUME_RE = re.compile(r"(?i)r[eé]sum[eé]")
_MESSAGES_RE = re.compile(r"(?i)messages?\s+cl[eé]s?")
_DATE_VALID_RE = re.compile(r"(?i)date\s+de\s+validation\s*:\s*(\d{1,2}\s+\w+\s+\d{4})")

# Patterns spécifiques aux pages CT (Commission de la Transparence)
_CT_SMR_RE = re.compile(r"(?i)service\s+m[eé]dical\s+rendu|^SMR$|\bSMR\b")
_CT_ASMR_RE = re.compile(r"(?i)am[eé]lioration\s+du\s+service|^ASMR$|\bASMR\b")
_CT_INDICATION_RE = re.compile(r"(?i)indication(s)?\s+(th[eé]rapeutique|revendiqu)")
_CT_POPULATION_RE = re.compile(r"(?i)population\s+cible")
_CT_CONCLUSION_RE = re.compile(r"(?i)avis\s+de\s+la\s+commission|conclusion\s+de\s+la\s+commission")
# Détecte si l'URL est une page CT (avis médicament) ou une RBP
_CT_URL_RE = re.compile(r"(?i)/jcms/[a-z]_\d+/fr/avis|/jcms/p_\d+/fr/.*-avis-")


def scrape_has_ct_page(url: str) -> dict[str, Any]:
    """
    Scrape une page HAS Commission de la Transparence (avis médicament).

    Structure typique :
      - Indication thérapeutique (DCI + pathologie)
      - SMR (Service médical rendu = niveau de remboursabilité)
      - ASMR (Amélioration du SMR = valeur ajoutée vs comparateur)
      - Population cible (estimation patients concernés)
      - Conclusion de la commission

    Ces informations sont directement actionnables pour prescripteurs+pharmaciens :
    → déremboursement (SMR insuffisant), nouveau remboursement, nouvelle indication.
    """
    result: dict[str, Any] = {
        "resume": None,
        "messages_cles": None,
        "date_validation": None,
        "type_doc": "HAS — Avis Commission de la Transparence",
        "is_scoping_doc": False,
    }

    html = _fetch_html(url)
    if not html:
        return result

    soup = BeautifulSoup(html, "html.parser")
    main_text = soup.get_text(" ", strip=True)

    # Date de l'avis
    m = _DATE_VALID_RE.search(main_text)
    if m:
        result["date_validation"] = m.group(1)

    # Indication : première section (DCI + pathologie = le quoi)
    indication = _extract_text_block(soup, _CT_INDICATION_RE)

    # SMR : service médical rendu — "important", "modéré", "insuffisant"
    smr = _extract_text_block(soup, _CT_SMR_RE)

    # ASMR : niveau 1 (majeur) à 5 (inexistant) — valeur ajoutée vs comparateur
    asmr = _extract_text_block(soup, _CT_ASMR_RE)

    # Population cible
    pop = _extract_text_block(soup, _CT_POPULATION_RE)

    # Conclusion / synthèse de la commission
    conclusion = _extract_text_block(soup, _CT_CONCLUSION_RE)

    parts = []
    if indication:
        parts.append(f"Indication : {indication[:400]}")
    if smr:
        parts.append(f"SMR : {smr[:400]}")
    if asmr:
        parts.append(f"ASMR : {asmr[:400]}")
    if pop:
        parts.append(f"Population cible : {pop[:300]}")
    if conclusion:
        parts.append(f"Conclusion CT : {conclusion[:500]}")

    if parts:
        result["resume"] = "\n".join(parts)
    elif main_text:
        # Fallback : extrait le début de la page body
        result["resume"] = main_text[:1500]

    logger.info(
        "HAS CT scraper OK %s | SMR=%s | ASMR=%s",
        url, bool(smr), bool(asmr),
    )
    return result


def scrape_has_page(url: str, source: str | None = None) -> dict[str, Any]:
    """
    Scrape une page HAS.
    Route vers scrape_has_ct_page() pour les avis CT (source='has_ct'),
    sinon extraction RBP standard (résumé + messages clés).

    Retourne un dict :
      {
        "resume":        str | None,   # résumé clinique extrait
        "messages_cles": str | None,   # messages clés extraits
        "date_validation": str | None, # ex. "08 janvier 2026"
        "type_doc":      str | None,   # ex. "Recommandation de bonne pratique"
        "is_scoping_doc": bool,        # True si Note de cadrage détectée
      }
    """
    # Route CT : source='has_ct' ou URL contenant les patterns d'un avis CT
    if source == "has_ct" or _CT_URL_RE.search(url or ""):
        return scrape_has_ct_page(url)
    result: dict[str, Any] = {
        "resume": None,
        "messages_cles": None,
        "date_validation": None,
        "type_doc": None,
        "is_scoping_doc": False,
    }

    html = _fetch_html(url)
    if not html:
        return result

    soup = BeautifulSoup(html, "html.parser")

    # ── Type de document ──────────────────────────────────────────────────────
    # HAS affiche le type comme "Recommandation de bonne pratique – Mis en ligne …"
    for tag in soup.find_all(string=re.compile(r"(?i)recommandation|guide maladie|évaluation")):
        text = tag.strip()
        if len(text) < 120:
            result["type_doc"] = text[:100]
            break

    # Vérifie si c'est un document de cadrage malgré le filtre amont
    page_title = soup.title.get_text() if soup.title else ""
    full_text_sample = page_title + " " + (result["type_doc"] or "")
    if _SCOPING_DOC_RE.search(full_text_sample):
        result["is_scoping_doc"] = True
        logger.debug("HAS scraper: scoping doc détecté, pas d'extraction → %s", url)
        return result

    # ── Date de validation ────────────────────────────────────────────────────
    main_text = soup.get_text(" ", strip=True)
    m = _DATE_VALID_RE.search(main_text)
    if m:
        result["date_validation"] = m.group(1)

    # ── Résumé ────────────────────────────────────────────────────────────────
    # Cherche d'abord l'ancre #résumé ou section id="resume"
    resume_section = soup.find(id=re.compile(r"(?i)r[eé]sum[eé]"))
    if resume_section:
        text = resume_section.get_text(" ", strip=True)
        if len(text) > 50:
            result["resume"] = text[:2000]
    # Fallback : cherche un heading "Résumé"
    if not result["resume"]:
        result["resume"] = _extract_text_block(soup, _RESUME_RE) or None

    # ── Messages clés ─────────────────────────────────────────────────────────
    messages_section = soup.find(id=re.compile(r"(?i)messages?[-_]?cl[eé]s?"))
    if messages_section:
        text = messages_section.get_text(" ", strip=True)
        if len(text) > 30:
            result["messages_cles"] = text[:2000]
    if not result["messages_cles"]:
        result["messages_cles"] = _extract_text_block(soup, _MESSAGES_RE) or None

    logger.info(
        "HAS scraper OK %s | résumé=%d | messages=%d",
        url,
        len(result["resume"] or ""),
        len(result["messages_cles"] or ""),
    )
    return result


def build_enriched_content(rss_summary: str | None, scraped: dict[str, Any]) -> str | None:
    """
    Fusionne le résumé RSS (souvent vide) avec le contenu scrapé HAS.
    Retourne une chaîne enrichie pour content_raw.
    """
    parts: list[str] = []

    if scraped.get("resume"):
        parts.append(f"[Résumé HAS] {scraped['resume']}")
    if scraped.get("messages_cles"):
        parts.append(f"[Messages clés] {scraped['messages_cles']}")
    if rss_summary and rss_summary not in (p for p in parts):
        parts.append(f"[RSS] {rss_summary}")

    return "\n\n".join(parts)[:4000] if parts else rss_summary
