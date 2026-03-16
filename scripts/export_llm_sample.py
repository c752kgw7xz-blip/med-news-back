#!/usr/bin/env python3
"""Export all PENDING articles to a Markdown file for audit."""

import os
import sys
import json

from dotenv import load_dotenv

# ── Load env ──────────────────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("✗ DATABASE_URL manquant dans .env")
    sys.exit(1)

import psycopg

OUTPUT = os.path.join(os.path.dirname(__file__), "..", "export_pending.md")


def main():
    conn = psycopg.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    c.title_raw        AS title,
                    c.source           AS source,
                    i.score_density    AS score,
                    i.audience         AS audience,
                    i.specialty_slug   AS specialty_slugs,
                    i.tri_json->>'resume'         AS summary,
                    i.lecture_json->'points_cles' AS key_points,
                    i.lecture_json->>'texte_long' AS analysis,
                    c.official_url     AS url
                FROM items i
                JOIN candidates c ON c.id = i.candidate_id
                WHERE i.review_status = 'PENDING'
                ORDER BY i.score_density DESC, c.source;
            """)
            rows = cur.fetchall()
    finally:
        conn.close()

    if not rows:
        print("✗ Aucun article PENDING trouvé.")
        sys.exit(1)

    lines = [
        f"# Export PENDING — {len(rows)} articles (audit)\n\n",
        f"_Généré automatiquement_\n\n",
    ]

    for r in rows:
        (title, source, score, audience, specialty_slugs,
         summary, key_points_raw, analysis, url) = r

        score_str = f"{score}/10" if score is not None else "—/10"
        source_str = source or "—"
        audience_str = audience or "—"
        title_str = title or "—"
        spec_str = specialty_slugs or "—"
        summary_str = summary or "—"
        analysis_str = analysis or "—"
        url_str = url or "—"

        # key_points: JSONB array → list of strings
        if key_points_raw:
            if isinstance(key_points_raw, str):
                try:
                    key_points_raw = json.loads(key_points_raw)
                except Exception:
                    key_points_raw = []
            points = key_points_raw if isinstance(key_points_raw, list) else []
        else:
            points = []

        lines.append("---\n\n")
        lines.append(f"## [{score_str}] {source_str} — {audience_str}\n\n")
        lines.append(f"**Titre :** {title_str}\n\n")
        lines.append(f"**Spécialités :** {spec_str}\n\n")
        lines.append(f"**Résumé :** {summary_str}\n\n")
        lines.append("**Points clés :**\n")
        if points:
            for p in points:
                if p and str(p).strip():
                    lines.append(f"- {str(p).strip()}\n")
        else:
            lines.append("- —\n")
        lines.append("\n")
        lines.append(f"**Analyse :** {analysis_str}\n\n")
        lines.append(f"**URL :** {url_str}\n\n")

    lines.append("---\n")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.writelines(lines)

    abs_path = os.path.abspath(OUTPUT)
    print(f"✓ {len(rows)} articles PENDING exportés → {abs_path}")


if __name__ == "__main__":
    main()
