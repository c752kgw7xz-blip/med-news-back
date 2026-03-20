#!/usr/bin/env python3
"""
scripts/test_collect_dry_run.py
─────────────────────────────────────────────────────────────────────────────
Dry-run du collect RSS : fetch les feeds, applique le pré-filtre, affiche
les stats et un aperçu des titres — SANS écrire en base ni appeler le LLM.

Usage :
    # Depuis la racine du projet
    python scripts/test_collect_dry_run.py

    # Tester un sous-ensemble
    python scripts/test_collect_dry_run.py --sources cnge,sfc_recommandations,splf

    # Afficher aussi les titres filtrés
    python scripts/test_collect_dry_run.py --show-dropped

    # Modifier la fenêtre temporelle (défaut : 90 jours)
    python scripts/test_collect_dry_run.py --days 30

Dépendances :
    pip install feedparser httpx
    (pas besoin de la DB ni de la clé Anthropic)
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import date, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

# ── Dépendances optionnelles ──────────────────────────────────────────────
try:
    import feedparser
    import httpx
except ImportError:
    print("❌  Installe les dépendances : pip install feedparser httpx")
    sys.exit(1)

# ── Imports projet ─────────────────────────────────────────────────────────
# On ajoute le répertoire parent au path pour pouvoir importer app.*
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app.llm_analysis import pre_filter_candidate, NOISY_SOURCES, _passes_jorf_whitelist
    from app.rss_collector import FEEDS, _parse_entry_date, _entry_title, _entry_url, _entry_summary, _HEADERS, _JS_REDIRECT_RE
except ImportError as e:
    print(f"❌  Impossible d'importer app.* : {e}")
    print("    Lance ce script depuis la racine du projet.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Constantes d'affichage
# ─────────────────────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Feeds représentatifs pour le test rapide (si pas --sources spécifié)
DEFAULT_TEST_SOURCES = [
    "cnge",              # Médecine générale — haut volume
    "sfc_recommandations", # Cardiologie — standard
    "splf",              # Pneumologie
    "snfge",             # Gastro-entérologie
    "sfdermato",         # Dermatologie — nouveau feed
    "sofcot",            # Chirurgie orthopédique — plus bruyant
    "has_ct",            # HAS Commission Transparence
    "spf_beh",           # Santé publique France
    "cnom",              # Ordre des Médecins — source bruyante avec whitelist
    "has_rbp",           # HAS RBP — référence de qualité
]


# ─────────────────────────────────────────────────────────────────────────────
# Fetch RSS (copie allégée de rss_collector.fetch_feed)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_feed(url: str, timeout: int = 20) -> feedparser.FeedParserDict | None:
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
                    r = client.get(redirect_url)
                    r.raise_for_status()
            return feedparser.parse(r.text)
    except Exception as e:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Catégorisation heuristique (pour l'affichage uniquement)
# ─────────────────────────────────────────────────────────────────────────────

_CAT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("RECOMMANDATION", re.compile(
        r"recommandation|guideline|référentiel|consensus|position\s+statement"
        r"|prise\s+en\s+charge|protocole|parcours|mise\s+à\s+jour\s+des",
        re.I
    )),
    ("CONGRÈS/ÉVÉNEMENT", re.compile(
        r"congrès|symposium|journée|séminaire|programme|inscription"
        r"|save\s+the\s+date|j-\d+|formation|webinaire|workshop",
        re.I
    )),
    ("ALERTE/SÉCURITÉ", re.compile(
        r"alerte|retrait|rupture|contre-indication|rappel|vigilance",
        re.I
    )),
    ("COMMUNIQUÉ/INSTITUTIONNEL", re.compile(
        r"communiqué|prix|nomination|élection|bureau|rapport\s+moral"
        r"|assemblée|partenariat|déontologie",
        re.I
    )),
    ("EXERCICE/TARIFS", re.compile(
        r"remboursement|tarif|honoraires|ccam|ngap|convention|avenant",
        re.I
    )),
]

def _categorize(title: str) -> str:
    for label, pat in _CAT_PATTERNS:
        if pat.search(title):
            return label
    return "AUTRE"


# ─────────────────────────────────────────────────────────────────────────────
# Analyse d'un feed
# ─────────────────────────────────────────────────────────────────────────────

def analyse_feed(feed_config: dict, days: int, show_dropped: bool) -> dict:
    source = feed_config["source"]
    url    = feed_config["url"]
    today  = date.today()
    start  = today - timedelta(days=days)

    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}[{source}]{RESET}  {feed_config.get('label', url)}")
    print(f"  URL : {url}")

    parsed = fetch_feed(url)
    if parsed is None or not hasattr(parsed, "entries") or not parsed.entries:
        print(f"  {RED}✗ Feed inaccessible ou vide{RESET}")
        return {"source": source, "error": True}

    entries = parsed.entries or []

    stats = defaultdict(int)
    kept_items   : list[dict] = []
    dropped_items: list[dict] = []

    for entry in entries:
        title    = _entry_title(entry)
        pub_date = _parse_entry_date(entry) or today
        entry_url = _entry_url(entry)
        summary  = _entry_summary(entry)

        if not title:
            stats["skip_no_title"] += 1
            continue

        stats["seen"] += 1

        # Filtre date
        if pub_date < start or pub_date > today:
            stats["skip_date"] += 1
            continue

        # Pré-filtre heuristique
        keep, drop_reason = pre_filter_candidate(title, source=source)
        if not keep:
            stats["drop_prefilter"] += 1
            dropped_items.append({"title": title, "date": pub_date, "reason": drop_reason, "cat": _categorize(title)})
            continue

        # Filtre whitelist sources bruyantes
        if source in NOISY_SOURCES and not _passes_jorf_whitelist(title):
            stats["drop_noisy"] += 1
            dropped_items.append({"title": title, "date": pub_date, "reason": "noisy_whitelist", "cat": _categorize(title)})
            continue

        # Article retenu pour le LLM
        stats["kept"] += 1
        has_summary = bool(summary and len(summary.strip()) > 50)
        kept_items.append({
            "title": title,
            "date": pub_date,
            "cat": _categorize(title),
            "has_summary": has_summary,
            "url": entry_url,
        })

    total_in_window = stats["seen"] - stats["skip_date"]
    kept  = stats["kept"]
    total_skipped = stats["drop_prefilter"] + stats["drop_noisy"]
    pct_kept = int(100 * kept / total_in_window) if total_in_window else 0

    # ── Affichage stats ──
    print(f"  Articles dans le flux       : {stats['seen']}")
    print(f"  Dans la fenêtre {days}j        : {total_in_window}")
    print(f"  {GREEN}✓ Retenus pour LLM          : {kept} ({pct_kept}%){RESET}")
    print(f"  {YELLOW}✗ Filtrés (pré-filtre)      : {stats['drop_prefilter']}{RESET}")
    if stats["drop_noisy"]:
        print(f"  {YELLOW}✗ Filtrés (whitelist)       : {stats['drop_noisy']}{RESET}")

    # ── Catégories des articles retenus ──
    if kept_items:
        cats = defaultdict(int)
        no_summary = 0
        for item in kept_items:
            cats[item["cat"]] += 1
            if not item["has_summary"]:
                no_summary += 1
        print(f"\n  {BOLD}Catégories (retenus) :{RESET}")
        for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
            bar = "█" * count
            print(f"    {cat:<30} {count:>3}  {bar}")
        if no_summary:
            print(f"  {YELLOW}⚠  {no_summary} article(s) sans résumé (titre seul pour le LLM){RESET}")

    # ── Aperçu des titres retenus (5 premiers) ──
    if kept_items:
        print(f"\n  {BOLD}Aperçu — articles retenus :{RESET}")
        for item in kept_items[:5]:
            summary_flag = "📄" if item["has_summary"] else "📋"
            print(f"    {summary_flag} [{item['date']}] {item['title'][:80]}")
        if len(kept_items) > 5:
            print(f"    … et {len(kept_items)-5} autres")

    # ── Aperçu des titres filtrés (si demandé) ──
    if show_dropped and dropped_items:
        print(f"\n  {BOLD}Aperçu — articles filtrés :{RESET}")
        for item in dropped_items[:8]:
            print(f"    {RED}✗{RESET} [{item['reason'][:25]}] {item['title'][:70]}")
        if len(dropped_items) > 8:
            print(f"    … et {len(dropped_items)-8} autres")

    return {
        "source"       : source,
        "seen"         : stats["seen"],
        "in_window"    : total_in_window,
        "kept"         : kept,
        "pct_kept"     : pct_kept,
        "drop_prefilter": stats["drop_prefilter"],
        "drop_noisy"   : stats["drop_noisy"],
        "error"        : False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Récapitulatif global
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: list[dict]) -> None:
    ok = [r for r in results if not r.get("error")]
    if not ok:
        return

    total_seen  = sum(r["in_window"] for r in ok)
    total_kept  = sum(r["kept"] for r in ok)
    total_drop  = sum(r["drop_prefilter"] + r["drop_noisy"] for r in ok)
    pct_global  = int(100 * total_kept / total_seen) if total_seen else 0

    print(f"\n\n{'═'*70}")
    print(f"{BOLD}RÉCAPITULATIF GLOBAL — {len(ok)} feeds testés{RESET}")
    print(f"{'═'*70}")
    print(f"  Articles vus (dans la fenêtre) : {total_seen}")
    print(f"  {GREEN}✓ Retenus pour LLM             : {total_kept} ({pct_global}%){RESET}")
    print(f"  {YELLOW}✗ Filtrés avant LLM            : {total_drop}{RESET}")
    print()

    # Tableau trié par % retenus
    print(f"  {'Source':<30} {'Vus':>5}  {'Gardés':>7}  {'Filtrés':>8}  {'%gardés':>8}")
    print(f"  {'─'*30}  {'─'*5}  {'─'*7}  {'─'*8}  {'─'*8}")
    for r in sorted(ok, key=lambda x: -x["pct_kept"]):
        color = GREEN if r["pct_kept"] >= 40 else (YELLOW if r["pct_kept"] >= 20 else RED)
        print(
            f"  {r['source']:<30} "
            f"{r['in_window']:>5}  "
            f"{r['kept']:>7}  "
            f"{r['drop_prefilter']+r['drop_noisy']:>8}  "
            f"{color}{r['pct_kept']:>7}%{RESET}"
        )

    print()
    print(f"  {BOLD}Estimation coût LLM (Claude Haiku){RESET}")
    print(f"  ~{total_kept} appels × ~800 tokens ≈ {total_kept*800//1000} k tokens")
    print(f"  Coût indicatif : {total_kept * 0.0004:.2f} USD (input) + {total_kept * 0.0016:.2f} USD (output)")
    print(f"  {'─'*40}")
    print(f"  Total estimé : ~{total_kept * 0.002:.2f} USD pour ce lot")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Dry-run collect RSS MedNews")
    parser.add_argument(
        "--sources", default=None,
        help="Comma-separated list of source keys (default: 10 feeds représentatifs)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Tester TOUS les feeds (long)"
    )
    parser.add_argument(
        "--days", type=int, default=90,
        help="Fenêtre temporelle en jours (défaut: 90)"
    )
    parser.add_argument(
        "--show-dropped", action="store_true",
        help="Afficher les titres filtrés (pour calibrer le pré-filtre)"
    )
    args = parser.parse_args()

    # Sélection des feeds à tester
    if args.all:
        test_feeds = FEEDS
    elif args.sources:
        wanted = set(args.sources.split(","))
        test_feeds = [f for f in FEEDS if f["source"] in wanted]
        missing = wanted - {f["source"] for f in test_feeds}
        if missing:
            print(f"{YELLOW}⚠  Sources inconnues ignorées : {missing}{RESET}")
    else:
        wanted = set(DEFAULT_TEST_SOURCES)
        test_feeds = [f for f in FEEDS if f["source"] in wanted]

    if not test_feeds:
        print(f"{RED}Aucun feed trouvé.{RESET}")
        sys.exit(1)

    print(f"{BOLD}MedNews — Dry-run collect RSS{RESET}")
    print(f"Fenêtre : {args.days} jours  |  Feeds : {len(test_feeds)}")
    print(f"Mode : {'TOUS les feeds' if args.all else ', '.join(f['source'] for f in test_feeds)}")

    results = []
    for feed in test_feeds:
        result = analyse_feed(feed, days=args.days, show_dropped=args.show_dropped)
        results.append(result)

    print_summary(results)


if __name__ == "__main__":
    main()
