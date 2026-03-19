#!/usr/bin/env python3
"""
check_societes_savantes_rss.py
Teste les flux RSS candidats des sociétés savantes médicales françaises
via l'endpoint /admin/sources/test-feed du serveur Render.

Usage :
    python scripts/check_societes_savantes_rss.py

Prérequis :
    pip install httpx
"""

import httpx
import json
import time

BASE_URL = "https://med-news-back-fmgu.onrender.com"
ADMIN_SECRET = "mon-secret-admin"

# ---------------------------------------------------------------------------
# Candidats RSS à tester
# Patterns standards WordPress/Drupal/custom pour chaque société
# ---------------------------------------------------------------------------

CANDIDATES = [
    # ── Médecine générale ─────────────────────────────────────────────────
    {
        "source": "sfmg",
        "label": "SFMG — Médecine générale",
        "specialty": "medecine-generale",
        "urls": [
            "http://www.sfmg.org/rss/actualites_2-4-5-10-14-18.xml",
            "https://www.sfmg.org/rss/",
            "https://www.sfmg.org/feed",
        ],
    },
    {
        "source": "cnge",
        "label": "CNGE — Généralistes enseignants",
        "specialty": "medecine-generale",
        "urls": [
            "https://www.cnge.fr/feed",
            "https://www.cnge.fr/rss.xml",
            "https://cnge.fr/feed",
        ],
    },
    {
        "source": "snfmi",
        "label": "SNFMI — Médecine interne",
        "specialty": "medecine-interne",
        "urls": [
            "https://www.snfmi.org/feed",
            "https://www.snfmi.org/rss.xml",
            "https://snfmi.org/feed",
        ],
    },

    # ── Cardiologie / HTA ─────────────────────────────────────────────────
    {
        "source": "sfhta",
        "label": "SFHTA — Hypertension artérielle",
        "specialty": "cardiologie",
        "urls": [
            "https://www.sfhta.eu/feed",
            "https://www.sfhta.eu/rss.xml",
            "https://sfhta.eu/feed",
        ],
    },
    {
        "source": "cardio_online",
        "label": "Cardio-online (bras média SFC)",
        "specialty": "cardiologie",
        "urls": [
            "https://www.cardio-online.fr/feed",
            "https://www.cardio-online.fr/rss.xml",
            "https://cardio-online.fr/feed",
        ],
    },

    # ── Urgences / Réanimation / Anesthésie ───────────────────────────────
    {
        "source": "sfar",
        "label": "SFAR — Anesthésie-Réanimation",
        "specialty": "anesthesie-reanimation",
        "urls": [
            "https://sfar.org/feed",
            "https://www.sfar.org/feed",
            "https://sfar.org/rss.xml",
            "https://sfar.org/actualites/feed",
        ],
    },
    {
        "source": "srlf",
        "label": "SRLF — Réanimation langue française",
        "specialty": "reanimation",
        "urls": [
            "https://www.srlf.org/feed",
            "https://srlf.org/feed",
            "https://www.srlf.org/rss.xml",
        ],
    },

    # ── Neurologie / Psychiatrie ──────────────────────────────────────────
    {
        "source": "sfn",
        "label": "SFN — Société Française de Neurologie",
        "specialty": "neurologie",
        "urls": [
            "https://www.sf-neuro.org/feed",
            "https://sf-neuro.org/feed",
            "https://www.sf-neuro.org/rss.xml",
            "https://www.sfneuro.org/feed",
        ],
    },
    {
        "source": "sfpsychiatrie",
        "label": "SFP — Psychiatrie",
        "specialty": "psychiatrie",
        "urls": [
            "https://www.sfpsy.org/feed",
            "https://sfpsy.org/feed",
            "https://www.sfpsy.org/rss.xml",
        ],
    },

    # ── Gastroentérologie / Hépatologie ───────────────────────────────────
    {
        "source": "snfge",
        "label": "SNFGE — Gastroentérologie",
        "specialty": "gastroenterologie",
        "urls": [
            "https://www.snfge.org/feed",
            "https://snfge.org/feed",
            "https://www.snfge.org/rss.xml",
            "https://www.snfge.org/actualites/feed",
        ],
    },
    {
        "source": "afef",
        "label": "AFEF — Hépatologie",
        "specialty": "hepatologie",
        "urls": [
            "https://afef.asso.fr/feed",
            "https://www.afef.asso.fr/feed",
            "https://afef.asso.fr/rss.xml",
        ],
    },

    # ── Pneumologie ───────────────────────────────────────────────────────
    {
        "source": "splf",
        "label": "SPLF — Pneumologie",
        "specialty": "pneumologie",
        "urls": [
            "https://splf.fr/feed",
            "https://www.splf.fr/feed",
            "https://splf.fr/rss.xml",
            "https://splf.fr/actualites/feed",
        ],
    },

    # ── Endocrinologie / Diabétologie ─────────────────────────────────────
    {
        "source": "sfendocrino",
        "label": "SFE — Endocrinologie",
        "specialty": "endocrinologie",
        "urls": [
            "https://www.sfendocrino.org/feed",
            "https://sfendocrino.org/feed",
            "https://www.sfendocrino.org/rss.xml",
        ],
    },
    {
        "source": "sfdiabete",
        "label": "SFD — Diabétologie",
        "specialty": "endocrinologie",
        "urls": [
            "https://www.sfdiabete.org/feed",
            "https://sfdiabete.org/feed",
            "https://www.sfdiabete.org/rss.xml",
        ],
    },

    # ── Rhumatologie ──────────────────────────────────────────────────────
    {
        "source": "sfrhumato",
        "label": "SFR — Rhumatologie",
        "specialty": "rhumatologie",
        "urls": [
            "https://www.larhumatologie.fr/feed",
            "https://larhumatologie.fr/feed",
            "https://www.larhumatologie.fr/rss.xml",
            "https://www.rheumatologie.asso.fr/feed",
        ],
    },

    # ── Néphrologie ───────────────────────────────────────────────────────
    {
        "source": "sfndt",
        "label": "SFNDT — Néphrologie",
        "specialty": "nephrologie",
        "urls": [
            "https://www.sfndt.org/feed",
            "https://sfndt.org/feed",
            "https://www.sfndt.org/rss.xml",
        ],
    },

    # ── Dermatologie ──────────────────────────────────────────────────────
    {
        "source": "sfdermato",
        "label": "SFD — Dermatologie",
        "specialty": "dermatologie",
        "urls": [
            "https://www.sfdermato.org/feed",
            "https://sfdermato.org/feed",
            "https://www.sfdermato.org/rss.xml",
            "https://dermato-info.fr/feed",
        ],
    },

    # ── Ophtalmologie ─────────────────────────────────────────────────────
    {
        "source": "sfo",
        "label": "SFO — Ophtalmologie",
        "specialty": "ophtalmologie",
        "urls": [
            "https://www.sfo-online.fr/feed",
            "https://sfo-online.fr/feed",
            "https://www.sfo-online.fr/rss.xml",
            "https://www.sfo.asso.fr/feed",
        ],
    },

    # ── ORL ───────────────────────────────────────────────────────────────
    {
        "source": "sforl",
        "label": "SFORL — ORL",
        "specialty": "orl",
        "urls": [
            "https://www.sforl.org/feed",
            "https://sforl.org/feed",
            "https://www.sforl.org/rss.xml",
            "https://www.sforl.com/feed",
        ],
    },

    # ── Urologie ──────────────────────────────────────────────────────────
    {
        "source": "afu",
        "label": "AFU — Urologie",
        "specialty": "urologie",
        "urls": [
            "https://www.urofrance.org/feed",
            "https://urofrance.org/feed",
            "https://www.urofrance.org/rss.xml",
        ],
    },

    # ── Infectiologie ─────────────────────────────────────────────────────
    {
        "source": "spilf",
        "label": "SPILF — Infectiologie",
        "specialty": "infectiologie",
        "urls": [
            "https://www.infectiologie.com/feed",
            "https://infectiologie.com/feed",
            "https://www.infectiologie.com/rss.xml",
            "https://www.infectiologie.com/UserFiles/File/rss/rss.xml",
        ],
    },

    # ── Gériatrie ─────────────────────────────────────────────────────────
    {
        "source": "sfgg",
        "label": "SFGG — Gériatrie",
        "specialty": "geriatrie",
        "urls": [
            "https://sfgg.org/feed",
            "https://www.sfgg.org/feed",
            "https://sfgg.org/rss.xml",
        ],
    },

    # ── Radiologie ────────────────────────────────────────────────────────
    {
        "source": "sfr_radio",
        "label": "SFR — Radiologie",
        "specialty": "radiologie",
        "urls": [
            "https://www.radiologie.fr/feed",
            "https://radiologie.fr/feed",
            "https://www.sfrnet.org/feed",
            "https://www.sfrnet.org/rss.xml",
        ],
    },

    # ── Hématologie ───────────────────────────────────────────────────────
    {
        "source": "sfh",
        "label": "SFH — Hématologie",
        "specialty": "hematologie",
        "urls": [
            "https://sfh.hematologie.net/feed",
            "https://www.sfh.hematologie.net/feed",
            "https://sfh.hematologie.net/rss.xml",
        ],
    },

    # ── Oncologie / Radiothérapie ─────────────────────────────────────────
    {
        "source": "sfro",
        "label": "SFRO — Radiothérapie oncologique",
        "specialty": "oncologie",
        "urls": [
            "https://www.sfro.fr/feed",
            "https://sfro.fr/feed",
            "https://www.sfro.org/feed",
            "https://sfro.org/feed",
        ],
    },
]


def test_url(url: str, timeout: int = 10) -> dict:
    try:
        resp = httpx.post(
            f"{BASE_URL}/admin/sources/test-feed",
            params={"url": url},
            headers={"x-admin-secret": ADMIN_SECRET},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                return {
                    "status": "ok",
                    "total_entries": data.get("total_entries", 0),
                    "feed_title": data.get("feed", {}).get("title", ""),
                    "sample_titles": [s.get("title", "") for s in data.get("sample", [])[:2]],
                }
            else:
                return {"status": "error", "error": data.get("error", "unknown")}
        return {"status": "http_error", "code": resp.status_code}
    except Exception as e:
        return {"status": "exception", "error": str(e)}


def main():
    print(f"\n{'='*70}")
    print("  SCAN RSS — SOCIÉTÉS SAVANTES MÉDICALES FRANÇAISES")
    print(f"{'='*70}\n")

    results = []

    for candidate in CANDIDATES:
        source = candidate["source"]
        label = candidate["label"]
        found_url = None
        found_result = None

        print(f"  Testing {label}...")

        for url in candidate["urls"]:
            result = test_url(url)
            time.sleep(0.3)  # éviter le rate-limit

            if result["status"] == "ok" and result["total_entries"] > 0:
                found_url = url
                found_result = result
                print(f"    ✅ {url} ({result['total_entries']} entries)")
                break
            else:
                print(f"    ❌ {url} → {result.get('error') or result.get('status')}")

        results.append({
            "source": source,
            "label": label,
            "specialty": candidate["specialty"],
            "url": found_url,
            "entries": found_result["total_entries"] if found_result else 0,
            "feed_title": found_result["feed_title"] if found_result else "",
            "sample": found_result["sample_titles"] if found_result else [],
        })
        print()

    # ── Résumé ──────────────────────────────────────────────────────────
    working = [r for r in results if r["url"]]
    dead    = [r for r in results if not r["url"]]

    print(f"\n{'='*70}")
    print(f"  RÉSULTAT : {len(working)}/{len(results)} sources avec RSS valide")
    print(f"{'='*70}\n")

    if working:
        print("✅ SOURCES VALIDES :\n")
        for r in working:
            print(f"  [{r['specialty']}] {r['label']}")
            print(f"    url   : {r['url']}")
            print(f"    entrées: {r['entries']}")
            if r["sample"]:
                print(f"    ex.   : {r['sample'][0][:80]}")
            print()

    if dead:
        print("❌ SANS RSS :\n")
        for r in dead:
            print(f"  [{r['specialty']}] {r['label']}")

    # ── Export JSON ──────────────────────────────────────────────────────
    output_path = "scripts/societes_savantes_rss_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"working": working, "dead": dead}, f, ensure_ascii=False, indent=2)
    print(f"\n→ Résultats exportés dans {output_path}")


if __name__ == "__main__":
    main()
