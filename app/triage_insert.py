"""
app/triage_insert.py
────────────────────
Protocole standard d'insertion manuelle (triage dans la conversation Claude).

Usage type :

    from app.triage_insert import item, run_insert

    ITEMS = [
        item(
            candidate_id="...",
            slug="cardiologie",
            categorie="therapeutique",       # therapeutique | clinique | exercice
            source_type="reglementaire",     # reglementaire | recommandation | innovation
            type_praticien="medecin-specialiste",
            score=75,
            titre="HAS — ...",
            resume="...",
            impact="...",
            date_pub="2026-04-14",
            url="https://...",
            points_cles=["...", "..."],
            texte_long="...",
            references=["..."],
        ),
    ]

    run_insert(
        items=ITEMS,
        mark_done_source="has_dm",   # UPDATE candidates SET status='LLM_DONE' WHERE source=...
        # ou mark_done_ids=[...] pour une liste d'UUIDs précis
    )

Règles éditoriales (à respecter avant d'appeler cette fonction) :
  - Ton : journal médical spécialisé (Anesthesiology, JVS, EJVES, BJA…)
  - resume    : phrase 1 = résultat chiffré (OR/HR/RR + IC95% + p) ; phrase 2 = design
  - impact    : conseil praticien-à-praticien, concret, actionnable
  - texte_long réglementaire : décision + cadre juridique + éligibilité + prescription + PEC
  - Jamais : mécanisme d'action, hedging académique, ouverture par la méthode
"""

from __future__ import annotations

import json
import os
from typing import Any

import psycopg2
from dotenv import load_dotenv

load_dotenv()

# ── Valeurs autorisées (CHECK CONSTRAINT PostgreSQL) ─────────────────────────
_VALID_SOURCE_TYPES   = {"reglementaire", "recommandation", "innovation"}
_VALID_CATEGORIES     = {"therapeutique", "clinique", "exercice"}
_VALID_PRATICIENS     = {
    "medecin-specialiste", "medecin-generaliste", "medecin",
    "interventionnel", "prescripteur",
}

_INSERT_SQL = """
INSERT INTO items
    (candidate_id, specialty_slug, audience, categorie, source_type, type_praticien,
     tri_json, lecture_json, score_density, review_status, llm_model, llm_created_at)
SELECT %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, 'PENDING', 'manual-triage', NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM items
    WHERE candidate_id = %s::uuid
      AND COALESCE(specialty_slug, '') = COALESCE(%s, '')
)
"""


def item(
    candidate_id: str,
    slug: str,
    categorie: str,
    source_type: str,
    type_praticien: str,
    score: int,
    titre: str,
    resume: str,
    impact: str,
    date_pub: str,
    url: str,
    points_cles: list[str],
    texte_long: str,
    references: list[str],
) -> dict[str, Any]:
    """Construit le dict d'un item prêt à être inséré."""
    if source_type not in _VALID_SOURCE_TYPES:
        raise ValueError(f"source_type invalide : {source_type!r} — valeurs : {_VALID_SOURCE_TYPES}")
    if categorie not in _VALID_CATEGORIES:
        raise ValueError(f"categorie invalide : {categorie!r} — valeurs : {_VALID_CATEGORIES}")

    return {
        "candidate_id":  candidate_id,
        "specialty_slug": slug,
        "audience":      "SPECIALITE",
        "categorie":     categorie,
        "source_type":   source_type,
        "type_praticien": type_praticien,
        "score_density": score,
        "tri_json": {
            "nature":           categorie,
            "titre_court":      titre,
            "resume":           resume,
            "impact_pratique":  impact,
            "date_publication": date_pub,
            "source_url":       url,
        },
        "lecture_json": {
            "references":  references,
            "texte_long":  texte_long,
            "points_cles": points_cles,
        },
    }


def run_insert(
    items: list[dict[str, Any]],
    mark_done_source: str | None = None,
    mark_done_ids: list[str] | None = None,
) -> None:
    """
    Insère les items (PENDING) et marque les candidats comme LLM_DONE.

    Paramètres
    ----------
    items             : liste produite par item()
    mark_done_source  : source à passer en LLM_DONE (ex : "has_dm")
    mark_done_ids     : liste d'UUIDs de candidates à passer en LLM_DONE
                        (utilisé quand plusieurs sources sont mélangées dans un même script)
    """
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur  = conn.cursor()

    inserted = 0
    skipped  = 0

    for it in items:
        cur.execute(
            _INSERT_SQL,
            (
                it["candidate_id"], it["specialty_slug"], it["audience"],
                it["categorie"],    it["source_type"],    it["type_praticien"],
                json.dumps(it["tri_json"],     ensure_ascii=False),
                json.dumps(it["lecture_json"], ensure_ascii=False),
                it["score_density"],
                # params WHERE NOT EXISTS
                it["candidate_id"], it["specialty_slug"],
            ),
        )
        if cur.rowcount:
            inserted += 1
        else:
            skipped += 1

    print(f"Items insérés  : {inserted}")
    print(f"Items existants: {skipped}")

    # ── Marquer les candidats LLM_DONE ───────────────────────────────────────
    if mark_done_source:
        cur.execute(
            "UPDATE candidates SET status='LLM_DONE' WHERE source=%s AND status='NEW'",
            (mark_done_source,),
        )
        print(f"Candidats {mark_done_source!r} → LLM_DONE : {cur.rowcount}")

    if mark_done_ids:
        cur.execute(
            "UPDATE candidates SET status='LLM_DONE' WHERE id = ANY(%s::uuid[]) AND status='NEW'",
            (mark_done_ids,),
        )
        print(f"Candidats (liste) → LLM_DONE : {cur.rowcount}")

    conn.commit()
    conn.close()
    print("✓ Terminé.")
