# app/rss_collector.py
"""
Collecteurs RSS — sources officielles de santé française.
URLs vérifiées directement sur les sites officiels.

Sources retenues :
  HAS  : Recommandations de bonne pratique uniquement
         → changement de pratique clinique pour les médecins
  ANSM : Alertes sécurité médicaments + ruptures d'appro
         → retraits AMM, contre-indications nouvelles, tensions stock
  BO   : Bulletins officiels ministères sociaux
         → circulaires ministère santé hors JORF

Sources exclues et pourquoi :
  - HAS commission transparence / DM / accès précoce → décisions industrie pharma
  - ANSM actualités générales → bruit, doublon avec alertes ciblées
  - Santé publique France → épidémiologie, pas réglementaire
  - LEGI codes consolidés → doublon tardif du JORF
"""

from __future__ import annotations

import logging
import re
from datetime import date, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import httpx

from app.collector_utils import build_candidate_row, insert_candidate
from app.db import get_conn
from app.llm_analysis import pre_filter_candidate, NOISY_SOURCES, _passes_jorf_whitelist
from app.sources_pratique import ALL_PRATIQUE_FEEDS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flux RSS — définition
# Toutes les URLs ont été vérifiées sur les sites officiels.
# ---------------------------------------------------------------------------

FEEDS: list[dict] = [

    # ── HAS : recommandations de bonne pratique uniquement ──────────────
    # Source : https://www.has-sante.fr/jcms/c_1771214/fr/nos-flux-d-information-rss
    # Inclus  : RBP, recommandations vaccinales, guides parcours, outils
    # Exclus  : avis médicaments (CT), avis DM, accès précoce, avis économiques
    {
        "url": "https://www.has-sante.fr/feed/Rss2.jsp?id=p_3081452",
        "label": "HAS — Recommandations et guides",
        "source": "has_rbp",
        "audience": ["medecins"],
    },

    # ── ANSM : alertes de sécurité médicaments ───────────────────────────
    # Source : https://ansm.sante.fr/page/flux-rss
    # Inclus  : pharmacovigilance, retraits AMM, nouvelles contre-indications,
    #           restrictions d'utilisation, lettres aux professionnels de santé
    # Pertinent pour médecins (prescripteurs) ET pharmaciens
    {
        "url": "https://ansm.sante.fr/rss/informations_securite",
        "label": "ANSM — Informations de sécurité (pharmacovigilance)",
        "source": "ansm_securite",
        "audience": ["medecins", "pharmaciens"],
    },
    # Alertes sécurité filtrées médicaments uniquement
    {
        "url": "https://ansm.sante.fr/rss/informations_securite?produitsSante=medicaments",
        "label": "ANSM — Sécurité médicaments",
        "source": "ansm_securite_med",
        "audience": ["medecins", "pharmaciens"],
    },

    # ── ANSM : ruptures et tensions d'approvisionnement ──────────────────
    # Pertinent principalement pharmaciens, mais médecins doivent adapter
    # leurs prescriptions en cas de rupture d'un médicament courant
    {
        "url": "https://ansm.sante.fr/rss/disponibilite_produits_sante?produitsSante=medicaments",
        "label": "ANSM — Ruptures/tensions médicaments",
        "source": "ansm_ruptures_med",
        "audience": ["pharmaciens", "medecins"],
    },
    {
        "url": "https://ansm.sante.fr/rss/disponibilite_produits_sante?produitsSante=vaccins",
        "label": "ANSM — Disponibilité vaccins",
        "source": "ansm_ruptures_vaccins",
        "audience": ["pharmaciens", "medecins"],
    },

    # ── Bulletins officiels ministères sociaux ────────────────────────────
    # Source : https://bulletins-officiels.social.gouv.fr
    # Contient les circulaires et instructions du ministère Santé
    # non publiées au JORF mais opposables aux professionnels
    {
        "url": "https://bulletins-officiels.social.gouv.fr/rss.xml",
        "label": "Bulletins officiels ministères sociaux",
        "source": "bo_social",
        "audience": ["medecins", "pharmaciens"],
    },

    # ── Santé publique France — articles (BEH inclus) ────────────────────
    # Source : https://www.santepubliquefrance.fr/flux-rss
    # RSS vérifié : flux général des articles SPF (inclut BEH, alertes, épidémiologie)
    # Note légale : SPF est un organisme public ; usage professionnel de veille
    #               couvert par la Loi République Numérique (2016, données publiques).
    #               CGU SPF mentionnent "usage personnel" pour RSS — à surveiller.
    # Contenu : données surveillance, alertes sanitaires, épidémies, vaccination
    # Filtre LLM : min_llm_score=5 — seules les alertes actionnables passent
    {
        "url": "https://www.santepubliquefrance.fr/rss/types-de-documents/article.xml",
        "label": "Santé publique France — Articles (BEH, alertes, épidémiologie)",
        "source": "spf_beh",
        "audience": ["medecins"],
    },

    # ── Ordre National des Médecins (CNOM) — déontologie, exercice ───────
    # Source : https://www.conseil-national.medecin.fr
    # RSS vérifié actif (mars 2026) : /rss.xml — contenu récent confirmé
    # CGU (section 3.3) : RSS explicitement autorisé avec attribution de la source
    # Contenu : déontologie médicale, exercice libéral, réglementation professionnelle
    # Filtre LLM : require_whitelist=True + min_llm_score=5 — élimine le bruit institutionnel
    {
        "url": "https://www.conseil-national.medecin.fr/rss.xml",
        "label": "CNOM — Ordre National des Médecins",
        "source": "cnom",
        "audience": ["medecins"],
    },

    # ── Sources exclues après audit (mars 2026) ───────────────────────────
    # ameli_pro : login requis pour accès aux données professionnelles
    # inca      : aucun RSS ; réutilisation requiert autorisation préalable (servicejuridique@institutcancer.fr)
    # andpc     : aucun RSS (404) ; réutilisation digitale non autorisée par les CGU

    # ── Sources pratiques — recommandations cliniques et bon usage ────────
    # Importées depuis app/sources_pratique.py
    *ALL_PRATIQUE_FEEDS,
]


# ---------------------------------------------------------------------------
# Helpers RSS
# ---------------------------------------------------------------------------

def _parse_entry_date(entry: Any) -> date | None:
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            return date(*entry.published_parsed[:3])
        except Exception:
            pass
    if hasattr(entry, "updated_parsed") and entry.updated_parsed:
        try:
            return date(*entry.updated_parsed[:3])
        except Exception:
            pass
    for attr in ("published", "updated"):
        raw = getattr(entry, attr, None)
        if raw:
            try:
                return parsedate_to_datetime(raw).date()
            except Exception:
                pass
    return None


def _entry_id(entry: Any, feed_url: str) -> str:
    return (
        getattr(entry, "id", None)
        or getattr(entry, "link", None)
        or f"{feed_url}::{getattr(entry, 'title', '')}"
    )


def _entry_url(entry: Any) -> str:
    return getattr(entry, "link", "") or ""


def _entry_title(entry: Any) -> str:
    return (getattr(entry, "title", "") or "").strip()


def _entry_summary(entry: Any) -> str | None:
    summary = getattr(entry, "summary", None) or getattr(entry, "description", None)
    if summary:
        clean = re.sub(r"<[^>]+>", " ", summary)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean[:2000] if clean else None
    return None


_JS_REDIRECT_RE = re.compile(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]")

_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
}


def fetch_feed(feed_url: str, timeout: int = 20) -> feedparser.FeedParserDict | None:
    """
    Récupère un flux RSS.
    Gère les protections anti-bot par redirect JavaScript (ex: HAS) :
    la 1ère requête pose un cookie et retourne un path de redirect en JS ;
    on suit ce path manuellement avec le cookie pour obtenir le vrai RSS.
    """
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=_HEADERS) as client:
            r = client.get(feed_url)
            r.raise_for_status()

            # Détecte un redirect JS (anti-bot) : content-type HTML + window.location.href
            ct = r.headers.get("content-type", "")
            if "html" in ct:
                m = _JS_REDIRECT_RE.search(r.text)
                if m:
                    redirect_path = m.group(1)
                    base = str(r.url).split("/", 3)[:3]  # scheme + host
                    redirect_url = "/".join(base) + redirect_path
                    logger.debug("Fetch RSS %s → redirect JS → %s", feed_url, redirect_url)
                    r = client.get(redirect_url)
                    r.raise_for_status()

            return feedparser.parse(r.text)
    except Exception as e:
        logger.warning("Fetch RSS %s échoué : %s", feed_url, e)
        return None


# ---------------------------------------------------------------------------
# Collecteur d'un flux
# ---------------------------------------------------------------------------

def collect_feed(feed_config: dict, days: int = 35) -> dict[str, int]:
    url    = feed_config["url"]
    source = feed_config["source"]
    today  = date.today()
    start  = today - timedelta(days=days)

    parsed = fetch_feed(url)
    if parsed is None or not hasattr(parsed, "entries"):
        logger.warning("[%s] flux inaccessible", source)
        return {"seen": 0, "inserted": 0, "deduped": 0, "skipped": 0, "error": "fetch_failed"}

    entries = parsed.entries or []
    seen = inserted = deduped = skipped = 0

    with get_conn() as conn:
        with conn.cursor() as cur:
            for entry in entries:
                seen += 1
                title = _entry_title(entry)
                if not title:
                    skipped += 1
                    continue

                pub_date = _parse_entry_date(entry) or today
                if pub_date < start or pub_date > today:
                    skipped += 1
                    continue

                entry_id  = _entry_id(entry, url)
                entry_url = _entry_url(entry)
                summary   = _entry_summary(entry)

                if not entry_url:
                    skipped += 1
                    continue

                # ── Pré-filtre heuristique (0 appel LLM) ─────────────────────
                # 1. Filtre générique : nominations, événements, congrès...
                keep, drop_reason = pre_filter_candidate(title, source=source)
                if not keep:
                    logger.debug("[%s] pre_filter DROP '%s' (%s)", source, title[:60], drop_reason)
                    skipped += 1
                    continue
                # 2. Filtre whitelist médicale pour les sources bruyantes
                if source in NOISY_SOURCES and not _passes_jorf_whitelist(title):
                    logger.debug("[%s] noisy_source DROP '%s'", source, title[:60])
                    skipped += 1
                    continue

                raw_payload = {
                    "id": entry_id,
                    "title": title,
                    "link": entry_url,
                    "summary": summary,
                    "published": str(getattr(entry, "published", "")),
                    "feed_source": source,
                    "feed_label": feed_config.get("label", ""),
                    "audience": feed_config.get("audience", []),
                }

                row = build_candidate_row(
                    source=source,
                    external_id=entry_id,
                    official_url=entry_url,
                    official_date=pub_date,
                    title_raw=title,
                    content_raw=summary,
                    raw_payload=raw_payload,
                )

                if insert_candidate(cur, row):
                    inserted += 1
                else:
                    deduped += 1

        conn.commit()

    logger.info("[%s] vu=%d ins=%d dup=%d ign=%d", source, seen, inserted, deduped, skipped)
    return {"seen": seen, "inserted": inserted, "deduped": deduped, "skipped": skipped}


# ---------------------------------------------------------------------------
# Collecteur global
# ---------------------------------------------------------------------------

def collect_all_rss(days: int = 35) -> dict[str, Any]:
    """
    Lance la collecte de tous les flux RSS actifs.
    Appelé par le scheduler mensuel.
    """
    results = {}
    for feed in FEEDS:
        try:
            results[feed["source"]] = collect_feed(feed, days=days)
        except Exception as e:
            logger.error("[%s] erreur : %s", feed["source"], e)
            results[feed["source"]] = {"error": str(e)}
    return results


# ---------------------------------------------------------------------------
# Collecteurs par source (appelés depuis sources_routes.py)
# ---------------------------------------------------------------------------

def _collect_by_prefix(prefix: str, days: int = 35) -> dict[str, Any]:
    results = {}
    for feed in FEEDS:
        if feed["source"].startswith(prefix):
            try:
                results[feed["source"]] = collect_feed(feed, days=days)
            except Exception as e:
                logger.error("[%s] erreur : %s", feed["source"], e)
                results[feed["source"]] = {"error": str(e)}
    return results


def collect_has(days: int = 35) -> dict[str, Any]:
    return _collect_by_prefix("has", days)


def collect_ansm(days: int = 35) -> dict[str, Any]:
    return _collect_by_prefix("ansm", days)


def collect_spf(days: int = 35) -> dict[str, Any]:
    # Santé publique France est exclu des sources retenues (épidémiologie,
    # pas réglementaire — voir docstring module). Aucun feed n'a source "spf".
    return {"inserted": 0, "skipped": 0, "errors": 0, "note": "source spf non activée"}


def collect_pratique(days: int = 90) -> dict[str, Any]:
    """
    Collecte uniquement les sources pratiques médicales (recommandations,
    bon usage, sociétés savantes, académie de médecine).
    Par défaut days=90 pour capturer l'historique récent des nouveaux feeds.
    """
    results: dict[str, Any] = {}
    for feed in ALL_PRATIQUE_FEEDS:
        try:
            results[feed["source"]] = collect_feed(feed, days=days)
        except Exception as e:
            logger.error("[%s] erreur : %s", feed["source"], e)
            results[feed["source"]] = {"error": str(e)}
    return results
