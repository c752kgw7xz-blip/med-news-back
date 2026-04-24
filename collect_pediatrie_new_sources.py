#!/usr/bin/env python3
"""
Collecte ciblée pédiatrie — nouvelles sources uniquement (180 jours).
NE lance PAS le LLM : le triage se fait manuellement dans la conversation.
"""
import sys, os, re

# Charger DATABASE_URL depuis .env
_env = open(os.path.join(os.path.dirname(__file__), ".env")).read()
for line in _env.splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

sys.path.insert(0, os.path.dirname(__file__))

DAYS = 180

NEW_PUBMED = [
    "pubmed_lancet_child",
    "pubmed_j_pediatr",
    "pubmed_arch_pediatr",
    "pubmed_pidj",
    "pubmed_acta_paediatr",
    "pubmed_pediatr_neurol",
]

NEW_RSS = [       # sources_europe.py → rss_collector
    "gpip",
    "has_pediatrie",
    "nice_pediatrie",
]

def main():
    from app.pubmed_collector import PUBMED_SOURCES, collect_pubmed_source
    from app.sources_europe import ALL_EUROPE_FEEDS
    from app.rss_collector import collect_feed

    total = 0

    # ── PubMed ──────────────────────────────────────────────────────────────
    print("\n── PubMed (180 jours) ──")
    pub_map = {s["source"]: s for s in PUBMED_SOURCES}
    for key in NEW_PUBMED:
        src = pub_map.get(key)
        if not src:
            print(f"  ⚠️  {key} : introuvable"); continue
        try:
            r = collect_pubmed_source(src, days=DAYS)
            n = r.get("inserted", 0); total += n
            print(f"  ✅ {key} : {n} insérés  (fetched={r.get('fetched',0)}, dupes={r.get('duplicates',0)})")
        except Exception as e:
            print(f"  ❌ {key} : {e}")

    # ── RSS (GPIP, HAS, NICE) ────────────────────────────────────────────────
    print("\n── RSS européens ──")
    euro_map = {s["source"]: s for s in ALL_EUROPE_FEEDS}
    for key in NEW_RSS:
        feed = euro_map.get(key)
        if not feed:
            print(f"  ⚠️  {key} : introuvable"); continue
        try:
            r = collect_feed(feed, days=DAYS)
            n = r.get("inserted", 0); total += n
            print(f"  ✅ {key} : {n} insérés  (fetched={r.get('fetched',0)}, dupes={r.get('duplicates',0)})")
        except Exception as e:
            print(f"  ❌ {key} : {e}")

    print(f"\n{'='*50}")
    print(f"TOTAL insérés : {total}")
    print(f"{'='*50}")

    # Compter les NEW en base pour ces sources
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur = conn.cursor()
    all_sources = tuple(NEW_PUBMED + NEW_RSS)
    cur.execute(
        "SELECT source, COUNT(*) FROM candidates WHERE status='NEW' AND source = ANY(%s) GROUP BY 1 ORDER BY 2 DESC",
        (list(all_sources),)
    )
    rows = cur.fetchall()
    if rows:
        print(f"\nCandidats NEW en base par source :")
        for src, cnt in rows:
            print(f"  {src} : {cnt}")
        print(f"  TOTAL NEW : {sum(c for _,c in rows)}")
    else:
        print("\nAucun candidat NEW en base pour ces sources.")
    conn.close()

if __name__ == "__main__":
    main()
