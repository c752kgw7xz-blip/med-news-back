#!/usr/bin/env python3
"""
check_societes_savantes_rss.py
Détecte les flux RSS des sociétés savantes médicales françaises via :
  1. RSS autodiscovery  — balise <link rel="alternate" type="application/rss+xml">
  2. URLs candidates    — patterns /feed, /rss, /rss.xml, etc.
  3. Validation finale  — via /admin/sources/test-feed (Render)

Usage :
    python3 scripts/check_societes_savantes_rss.py

Prérequis :
    pip3 install httpx beautifulsoup4 lxml
"""

import httpx
import json
import re
import time
from urllib.parse import urljoin, urlparse

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("⚠️  beautifulsoup4 non installé — autodiscovery désactivé")
    print("   pip3 install beautifulsoup4 lxml\n")

BASE_URL   = "https://med-news-back-fmgu.onrender.com"
ADMIN_SECRET = "mon-secret-admin"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; MedNewsBot/1.0; RSS scanner)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ---------------------------------------------------------------------------
# Sociétés savantes à scanner
# Pour chaque société : homepage + patterns candidats en fallback
# ---------------------------------------------------------------------------

CANDIDATES = [
    # ── Médecine générale ─────────────────────────────────────────────────
    {
        "source": "sfmg",
        "label": "SFMG — Médecine générale",
        "specialty": "medecine-generale",
        "homepage": "https://www.sfmg.org/",
        "extra_urls": [
            "http://www.sfmg.org/rss/actualites_2-4-5-10-14-18.xml",
            "https://www.sfmg.org/rss/actualites.xml",
        ],
    },
    {
        "source": "cnge",
        "label": "CNGE — Généralistes enseignants",
        "specialty": "medecine-generale",
        "homepage": "https://www.cnge.fr/",
        "extra_urls": [],
    },
    {
        "source": "snfmi",
        "label": "SNFMI — Médecine interne",
        "specialty": "medecine-interne",
        "homepage": "https://www.snfmi.org/",
        "extra_urls": [],
    },

    # ── Cardiologie / HTA ─────────────────────────────────────────────────
    {
        "source": "sfhta",
        "label": "SFHTA — Hypertension artérielle",
        "specialty": "cardiologie",
        "homepage": "https://www.sfhta.eu/",
        "extra_urls": [],
    },
    {
        "source": "cardio_online",
        "label": "Cardio-online (bras média SFC)",
        "specialty": "cardiologie",
        "homepage": "https://www.cardio-online.fr/",
        "extra_urls": [],
    },

    # ── Urgences / Réanimation / Anesthésie ───────────────────────────────
    {
        "source": "sfar",
        "label": "SFAR — Anesthésie-Réanimation",
        "specialty": "anesthesie-reanimation",
        "homepage": "https://sfar.org/",
        "extra_urls": [
            "https://sfar.org/actualites/feed",
            "https://sfar.org/recommandations/feed",
        ],
    },
    {
        "source": "srlf",
        "label": "SRLF — Réanimation",
        "specialty": "reanimation",
        "homepage": "https://www.srlf.org/",
        "extra_urls": [],
    },

    # ── Neurologie / Psychiatrie ──────────────────────────────────────────
    {
        "source": "sfn",
        "label": "SFN — Neurologie",
        "specialty": "neurologie",
        "homepage": "https://www.sf-neuro.org/",
        "extra_urls": [
            "https://www.sf-neuro.org/actualites/feed",
        ],
    },
    {
        "source": "sfpsychiatrie",
        "label": "SFP — Psychiatrie",
        "specialty": "psychiatrie",
        "homepage": "https://www.sfpsy.org/",
        "extra_urls": [],
    },

    # ── Gastroentérologie / Hépatologie ───────────────────────────────────
    {
        "source": "snfge",
        "label": "SNFGE — Gastroentérologie",
        "specialty": "gastroenterologie",
        "homepage": "https://www.snfge.org/",
        "extra_urls": [
            "https://www.snfge.org/actualites/feed",
            "https://www.snfge.org/recommandations/feed",
        ],
    },
    {
        "source": "afef",
        "label": "AFEF — Hépatologie",
        "specialty": "hepatologie",
        "homepage": "https://afef.asso.fr/",
        "extra_urls": [],
    },

    # ── Pneumologie ───────────────────────────────────────────────────────
    {
        "source": "splf",
        "label": "SPLF — Pneumologie",
        "specialty": "pneumologie",
        "homepage": "https://splf.fr/",
        "extra_urls": [
            "https://splf.fr/actualites/feed",
            "https://splf.fr/recommandations/feed",
        ],
    },

    # ── Endocrinologie / Diabétologie ─────────────────────────────────────
    {
        "source": "sfendocrino",
        "label": "SFE — Endocrinologie",
        "specialty": "endocrinologie",
        "homepage": "https://www.sfendocrino.org/",
        "extra_urls": [],
    },
    {
        "source": "sfdiabete",
        "label": "SFD — Diabétologie",
        "specialty": "endocrinologie",
        "homepage": "https://www.sfdiabete.org/",
        "extra_urls": [],
    },

    # ── Rhumatologie ──────────────────────────────────────────────────────
    {
        "source": "sfrhumato",
        "label": "SFR — Rhumatologie",
        "specialty": "rhumatologie",
        "homepage": "https://www.larhumatologie.fr/",
        "extra_urls": [
            "https://www.rheumatologie.asso.fr/feed",
        ],
    },

    # ── Néphrologie ───────────────────────────────────────────────────────
    {
        "source": "sfndt",
        "label": "SFNDT — Néphrologie",
        "specialty": "nephrologie",
        "homepage": "https://www.sfndt.org/",
        "extra_urls": [],
    },

    # ── Dermatologie ──────────────────────────────────────────────────────
    {
        "source": "sfdermato",
        "label": "SFD — Dermatologie",
        "specialty": "dermatologie",
        "homepage": "https://www.sfdermato.org/",
        "extra_urls": [
            "https://dermato-info.fr/feed",
        ],
    },

    # ── Ophtalmologie ─────────────────────────────────────────────────────
    {
        "source": "sfo",
        "label": "SFO — Ophtalmologie",
        "specialty": "ophtalmologie",
        "homepage": "https://www.sfo-online.fr/",
        "extra_urls": [
            "https://www.sfo.asso.fr/feed",
        ],
    },

    # ── ORL ───────────────────────────────────────────────────────────────
    {
        "source": "sforl",
        "label": "SFORL — ORL",
        "specialty": "orl",
        "homepage": "https://www.sforl.org/",
        "extra_urls": [
            "https://www.sforl.com/feed",
        ],
    },

    # ── Urologie ──────────────────────────────────────────────────────────
    {
        "source": "afu",
        "label": "AFU — Urologie",
        "specialty": "urologie",
        "homepage": "https://www.urofrance.org/",
        "extra_urls": [],
    },

    # ── Infectiologie ─────────────────────────────────────────────────────
    {
        "source": "spilf",
        "label": "SPILF — Infectiologie",
        "specialty": "infectiologie",
        "homepage": "https://www.infectiologie.com/",
        "extra_urls": [
            "https://www.infectiologie.com/UserFiles/File/rss/rss.xml",
        ],
    },

    # ── Gériatrie ─────────────────────────────────────────────────────────
    {
        "source": "sfgg",
        "label": "SFGG — Gériatrie",
        "specialty": "geriatrie",
        "homepage": "https://sfgg.org/",
        "extra_urls": [],
    },

    # ── Radiologie ────────────────────────────────────────────────────────
    {
        "source": "sfr_radio",
        "label": "SFR — Radiologie",
        "specialty": "radiologie",
        "homepage": "https://www.radiologie.fr/",
        "extra_urls": [
            "https://www.sfrnet.org/feed",
        ],
    },

    # ── Hématologie ───────────────────────────────────────────────────────
    {
        "source": "sfh",
        "label": "SFH — Hématologie",
        "specialty": "hematologie",
        "homepage": "https://sfh.hematologie.net/",
        "extra_urls": [],
    },

    # ── Oncologie médicale ────────────────────────────────────────────────
    {
        "source": "sfro",
        "label": "SFRO — Radiothérapie oncologique",
        "specialty": "oncologie",
        "homepage": "https://www.sfro.fr/",
        "extra_urls": [],
    },
    {
        "source": "ffcd",
        "label": "FFCD — Cancérologie digestive",
        "specialty": "oncologie",
        "homepage": "https://www.ffcd.fr/",
        "extra_urls": [],
    },
    {
        "source": "unicancer",
        "label": "UNICANCER — Oncologie",
        "specialty": "oncologie",
        "homepage": "https://www.unicancer.fr/",
        "extra_urls": [],
    },

    # ── Chirurgie vasculaire ──────────────────────────────────────────────
    {
        "source": "scv",
        "label": "SCV — Chirurgie Vasculaire",
        "specialty": "chirurgie-vasculaire",
        "homepage": "https://www.chirurgievasculaire.fr/",
        "extra_urls": [
            "https://www.sfcv.org/feed",
            "https://sfcv.org/feed",
        ],
    },

    # ── Chirurgie thoracique / cardiaque ──────────────────────────────────
    {
        "source": "sfctcv",
        "label": "SFCTCV — Chirurgie Thoracique et Cardio-Vasculaire",
        "specialty": "chirurgie-thoracique",
        "homepage": "https://www.sfctcv.org/",
        "extra_urls": [],
    },

    # ── Chirurgie plastique ───────────────────────────────────────────────
    {
        "source": "sofcpre",
        "label": "SOFCPRE — Chirurgie Plastique Reconstructrice et Esthétique",
        "specialty": "chirurgie-plastique",
        "homepage": "https://www.sofcpre.fr/",
        "extra_urls": [
            "https://www.sfcpre.fr/feed",
        ],
    },

    # ── Neurochirurgie ────────────────────────────────────────────────────
    {
        "source": "sfnc",
        "label": "SFNC — Société Française de Neurochirurgie",
        "specialty": "neurochirurgie",
        "homepage": "https://www.sfneurochirurgie.fr/",
        "extra_urls": [],
    },

    # ── Colo-proctologie ──────────────────────────────────────────────────
    {
        "source": "snfcp",
        "label": "SNFCP — Colo-Proctologie",
        "specialty": "gastroenterologie",
        "homepage": "https://www.snfcp.org/",
        "extra_urls": [],
    },

    # ── Médecine physique et réadaptation ─────────────────────────────────
    {
        "source": "sofmer",
        "label": "SOFMER — Médecine Physique et Réadaptation",
        "specialty": "medecine-physique",
        "homepage": "https://www.sofmer.com/",
        "extra_urls": [
            "https://sofmer.com/feed",
        ],
    },

    # ── Allergologie ──────────────────────────────────────────────────────
    {
        "source": "sfa_allergo",
        "label": "SFA — Société Française d'Allergologie",
        "specialty": "allergologie",
        "homepage": "https://www.sfa-allergologie.org/",
        "extra_urls": [
            "https://sfa-allergologie.org/feed",
        ],
    },

    # ── Médecine vasculaire ───────────────────────────────────────────────
    {
        "source": "sfmv",
        "label": "SFMV — Société Française de Médecine Vasculaire",
        "specialty": "medecine-vasculaire",
        "homepage": "https://www.sf-mv.fr/",
        "extra_urls": [
            "https://sf-mv.fr/feed",
            "https://www.sfmv.fr/feed",
        ],
    },

    # ── Médecine du sport ─────────────────────────────────────────────────
    {
        "source": "sfms",
        "label": "SFMS — Société Française de Médecine du Sport",
        "specialty": "medecine-sport",
        "homepage": "https://www.sfms.asso.fr/",
        "extra_urls": [
            "https://sfms.asso.fr/feed",
        ],
    },

    # ── Addictologie ──────────────────────────────────────────────────────
    {
        "source": "sfa_addicto",
        "label": "SFA — Société Française d'Alcoologie",
        "specialty": "addictologie",
        "homepage": "https://www.sfalcoologie.asso.fr/",
        "extra_urls": [
            "https://sfalcoologie.asso.fr/feed",
            "https://www.fsfa.fr/feed",
        ],
    },

    # ── Anatomopathologie ─────────────────────────────────────────────────
    {
        "source": "sfpath",
        "label": "SFP — Société Française de Pathologie",
        "specialty": "anatomopathologie",
        "homepage": "https://www.sfpathol.org/",
        "extra_urls": [
            "https://sfpathol.org/feed",
        ],
    },

    # ── Médecine nucléaire ────────────────────────────────────────────────
    {
        "source": "sfmn",
        "label": "SFMN — Société Française de Médecine Nucléaire",
        "specialty": "medecine-nucleaire",
        "homepage": "https://www.sfmn.org/",
        "extra_urls": [
            "https://sfmn.org/feed",
        ],
    },

    # ── Gynécologie médicale ──────────────────────────────────────────────
    {
        "source": "fncgm",
        "label": "FNCGM — Fédération Nationale des Collèges de Gynécologie Médicale",
        "specialty": "gynecologie",
        "homepage": "https://www.gynecologie-medicale.com/",
        "extra_urls": [
            "https://gynecologie-medicale.com/feed",
        ],
    },

    # ── Stomatologie / Chirurgie maxillo-faciale ──────────────────────────
    {
        "source": "sfscmf",
        "label": "SFSCMF — Chirurgie Maxillo-Faciale",
        "specialty": "stomatologie",
        "homepage": "https://www.sfscmf.fr/",
        "extra_urls": [
            "https://sfscmf.fr/feed",
        ],
    },

    # ── Biologie médicale / Microbiologie ─────────────────────────────────
    {
        "source": "sfm_micro",
        "label": "SFM — Société Française de Microbiologie",
        "specialty": "biologie",
        "homepage": "https://www.sfm-microbiologie.org/",
        "extra_urls": [
            "https://sfm-microbiologie.org/feed",
        ],
    },

    # ── Médecine d'urgence (2e tentative) ────────────────────────────────
    {
        "source": "sfmu",
        "label": "SFMU — Médecine d'Urgence",
        "specialty": "medecine-urgences",
        "homepage": "https://www.sfmu.org/",
        "extra_urls": [
            "https://www.sfmu.org/feed",
            "https://sfmu.org/fr/feed",
        ],
    },

    # ── Pédiatrie (2e tentative) ──────────────────────────────────────────
    {
        "source": "sfpediatrie",
        "label": "SFP — Société Française de Pédiatrie",
        "specialty": "pediatrie",
        "homepage": "https://www.sfpediatrie.com/",
        "extra_urls": [
            "https://sfpediatrie.com/feed",
            "https://www.sfpediatrie.com/rss",
        ],
    },

    # ── Néonatologie ──────────────────────────────────────────────────────
    {
        "source": "sfnn",
        "label": "SFNN — Société Française de Néonatologie",
        "specialty": "pediatrie",
        "homepage": "https://www.sfnn.fr/",
        "extra_urls": [
            "https://sfnn.fr/feed",
        ],
    },

    # ── Santé publique ────────────────────────────────────────────────────
    {
        "source": "sfsp",
        "label": "SFSP — Société Française de Santé Publique",
        "specialty": "sante-publique",
        "homepage": "https://www.sfsp.fr/",
        "extra_urls": [
            "https://sfsp.fr/feed",
        ],
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def autodiscover_rss(homepage: str, timeout: int = 8) -> list[str]:
    """
    Récupère la homepage et cherche les balises RSS autodiscovery.
    Retourne la liste des URLs de flux trouvées.
    """
    if not BS4_AVAILABLE:
        return []
    try:
        resp = httpx.get(homepage, headers=HEADERS, timeout=timeout, follow_redirects=True)
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, "lxml")
        feeds = []
        # <link rel="alternate" type="application/rss+xml" href="...">
        # <link rel="alternate" type="application/atom+xml" href="...">
        for link in soup.find_all("link", rel="alternate"):
            t = link.get("type", "")
            if "rss" in t or "atom" in t:
                href = link.get("href", "")
                if href:
                    feeds.append(urljoin(homepage, href))
        # Also scan <a> tags mentioning RSS/feed
        if not feeds:
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if re.search(r"/(rss|feed|atom)(\.xml)?$", href, re.I):
                    feeds.append(urljoin(homepage, href))
        return feeds
    except Exception:
        return []


def test_feed_via_render(url: str, timeout: int = 15) -> dict:
    """Valide un flux RSS via l'endpoint test-feed du serveur Render."""
    try:
        resp = httpx.post(
            f"{BASE_URL}/admin/sources/test-feed",
            params={"url": url},
            headers={"x-admin-secret": ADMIN_SECRET},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok") and data.get("total_entries", 0) > 0:
                return {
                    "status": "ok",
                    "total_entries": data["total_entries"],
                    "feed_title": data.get("feed", {}).get("title", ""),
                    "sample": [s.get("title", "") for s in data.get("sample", [])[:2]],
                }
            return {"status": "empty_or_invalid"}
        return {"status": f"http_{resp.status_code}"}
    except Exception as e:
        return {"status": "exception", "error": str(e)[:60]}


def find_working_feed(candidate: dict) -> tuple[str | None, dict | None]:
    """
    Cherche un flux RSS valide pour une société.
    Ordre : autodiscovery → extra_urls → patterns génériques.
    """
    homepage = candidate["homepage"]
    base = homepage.rstrip("/")

    # 1. Autodiscovery
    discovered = autodiscover_rss(homepage)
    all_urls = discovered + candidate.get("extra_urls", [])

    # 2. Patterns génériques
    for pattern in ["/feed", "/rss", "/rss.xml", "/feed.xml",
                    "/actualites/feed", "/actualites/rss.xml",
                    "/news/feed", "/publications/feed"]:
        all_urls.append(base + pattern)

    # Dédoublonner en préservant l'ordre
    seen = set()
    unique_urls = []
    for u in all_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    for url in unique_urls:
        result = test_feed_via_render(url)
        time.sleep(0.4)
        if result["status"] == "ok":
            return url, result

    return None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*70}")
    print("  SCAN RSS — SOCIÉTÉS SAVANTES MÉDICALES FRANÇAISES")
    print(f"  {len(CANDIDATES)} sociétés • autodiscovery + patterns + validation Render")
    print(f"{'='*70}\n")

    working = []
    dead    = []

    for i, candidate in enumerate(CANDIDATES, 1):
        label = candidate["label"]
        print(f"[{i:02d}/{len(CANDIDATES)}] {label}")

        url, result = find_working_feed(candidate)

        if url:
            print(f"  ✅ {url}")
            print(f"     → {result['total_entries']} articles | {result.get('feed_title','')}")
            if result.get("sample"):
                print(f"     ex: {result['sample'][0][:75]}")
            working.append({
                "source": candidate["source"],
                "label": label,
                "specialty": candidate["specialty"],
                "homepage": candidate["homepage"],
                "rss_url": url,
                "total_entries": result["total_entries"],
                "feed_title": result.get("feed_title", ""),
                "sample": result.get("sample", []),
            })
        else:
            print(f"  ❌ aucun flux RSS valide")
            dead.append({
                "source": candidate["source"],
                "label": label,
                "specialty": candidate["specialty"],
                "homepage": candidate["homepage"],
            })
        print()

    # ── Résumé ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  RÉSULTAT FINAL : {len(working)}/{len(CANDIDATES)} sources avec RSS valide")
    print(f"{'='*70}\n")

    if working:
        print("✅ À AJOUTER dans sources_pratique.py :\n")
        for r in working:
            print(f"  [{r['specialty']}] {r['label']}")
            print(f"    source : {r['source']}")
            print(f"    url    : {r['rss_url']}")
            print(f"    entrées: {r['total_entries']}")
            print()

    if dead:
        print("❌ PAS DE RSS :\n")
        for r in dead:
            print(f"  [{r['specialty']}] {r['label']}  ({r['homepage']})")

    # Export JSON
    output = "scripts/societes_savantes_rss_results.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump({"working": working, "dead": dead}, f, ensure_ascii=False, indent=2)
    print(f"\n→ Résultats sauvegardés dans {output}")
    print("  Colle le contenu de ce fichier pour que je mette à jour sources_pratique.py\n")


if __name__ == "__main__":
    main()
