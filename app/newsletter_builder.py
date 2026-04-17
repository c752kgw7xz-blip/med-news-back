# app/newsletter_builder.py
"""
Construit le HTML de la newsletter pour une spécialité donnée.

Entrée  : liste d'items APPROVED pour cette spécialité (depuis DB)
Sortie  : (sujet_email: str, html: str, texte_plain: str)

Design :
  - Reprend le système de design du portal (thème adaptatif OS clair/sombre)
  - Chaque article = carte avec priorité, catégorie, titre, résumé, impact, lien
  - Ordre : score_density DESC (les plus importants en premier)
  - Séparation visuelle SPECIALITE / TRANSVERSAL si les deux présents
"""

from __future__ import annotations

import os
from datetime import date
from html import escape as _he
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Noms affichés des spécialités
# ---------------------------------------------------------------------------

SPECIALTY_LABELS: dict[str, str] = {
    # Médecine générale
    "medecine-generale": "Médecine générale",
    # Spécialités médicales
    "cardiologie": "Cardiologie",
    "dermatologie": "Dermatologie",
    "endocrinologie": "Endocrinologie",
    "gastro-enterologie": "Gastro-entérologie",
    "gynecologie": "Gynécologie",
    "neurologie": "Neurologie",
    "ophtalmologie": "Ophtalmologie",
    "orl": "ORL",
    "pediatrie": "Pédiatrie",
    "pneumologie": "Pneumologie",
    "psychiatrie": "Psychiatrie",
    "rhumatologie": "Rhumatologie",
    "urologie": "Urologie",
    "medecine-interne": "Médecine interne",
    "medecine-urgences": "Médecine d'urgences",
    "geriatrie": "Gériatrie",
    "medecine-physique": "Médecine physique et réadaptation",
    "oncologie": "Oncologie",
    "hematologie": "Hématologie",
    "infectiologie": "Infectiologie",
    "nephrologie": "Néphrologie",
    "radiologie": "Radiologie",
    "anesthesiologie": "Anesthésiologie",
    # Chirurgie
    "chirurgie": "Chirurgie",
    "chirurgie-vasculaire": "Chirurgie vasculaire",
    "chirurgie-orthopedique": "Chirurgie orthopédique",
    "chirurgie-thoracique": "Chirurgie thoracique",
    "chirurgie-plastique": "Chirurgie plastique",
    "neurochirurgie": "Neurochirurgie",
    "chirurgie-pediatrique": "Chirurgie pédiatrique",
    "chirurgie-cardiaque": "Chirurgie cardiaque",
    # Paramédicaux
    "infirmiers": "Infirmiers",
    "kinesitherapie": "Kinésithérapie",
    "sage-femme": "Sage-femme",
    "biologiste": "Biologie médicale",
    # Chirurgiens-dentistes et orthodontistes
    "dentiste": "Dentisterie",
    "orthodontiste": "Orthodontie",
    # Pharmaciens — slug 'pharmacien' (sans s) : utilisé par llm_routes.py
    # pour tous les items audience=PHARMACIENS (cf. llm_routes.py:193).
    "pharmacien": "Pharmacien d'officine",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_url(url: str) -> str:
    """Sanitize a URL: reject non-http(s) schemes (e.g. javascript:) and HTML-escape."""
    if not url or url == "#":
        return "#"
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return "#"
    return _he(url, quote=True)


MOIS_FR = {
    1: "jan.", 2: "fév.", 3: "mars", 4: "avr.", 5: "mai", 6: "juin",
    7: "juil.", 8: "août", 9: "sept.", 10: "oct.", 11: "nov.", 12: "déc.",
}

MOIS_FR_LONG = {
    1: "janvier", 2: "février", 3: "mars", 4: "avril", 5: "mai", 6: "juin",
    7: "juillet", 8: "août", 9: "septembre", 10: "octobre", 11: "novembre", 12: "décembre",
}


def _format_date(date_raw: str) -> str:
    """'2026-02-23' → '23 fév. 2026'"""
    try:
        d = date.fromisoformat(date_raw[:10])
        return f"{d.day} {MOIS_FR[d.month]} {d.year}"
    except Exception:
        return date_raw or ""


def _priority_label(score: int) -> tuple[str, str]:
    """Retourne (label, css_class) selon le score."""
    if score >= 8:
        return ("▲ À lire impérativement", "h")
    elif score >= 6:
        return ("↑ Important", "m")
    else:
        return ("À consulter", "l")


CAT_STYLES: dict[str, tuple[str, str]] = {
    "therapeutique":  ("Médicaments & Dispositifs", "cat-innovation"),
    "clinique":       ("Clinique",                  "cat-recommandation"),
    "exercice":       ("Exercice & Admin",           "cat-reglementation"),
    "innovation":     ("Innovation",                 "cat-innovation"),
    "recommandation": ("Recommandation",             "cat-recommandation"),
    "reglementation": ("Réglementation",             "cat-reglementation"),
}

# CTA text selon le type de source
_SOURCE_TYPE_CTA: dict[str, str] = {
    "journal":        "Lire l'article →",
    "press":          "Lire l'article →",
    "presse":         "Lire l'article →",
    "innovation":     "Voir l'étude →",
    "guideline":      "Lire la recommandation →",
    "regulatory":     "Lire le texte officiel →",
    "reglementation": "Lire le texte officiel →",
    "congress":       "Voir le highlight →",
    "device":         "Voir le dispositif →",
}

# ---------------------------------------------------------------------------
# CSS complet (thème adaptatif OS)
# ---------------------------------------------------------------------------

_CSS = """
@media (prefers-color-scheme: dark) {
  :root {
    --bg:       #17140C;
    --surface:  #1E1B12;
    --surface2: #252219;
    --border:   #342F24;
    --border2:  #4A4438;
    --text:     #EDE7DC;
    --text2:    #C6BEB4;
    --text3:    #8A8378;
    --text4:    #6A6360;
    --text5:    #504840;
    --accent:   #9B2335;
    --strip:    #1E1B12;
    --impact:   #252219;
  }
}
:root {
  --bg:       #F5F4EF;
  --surface:  #FDFCF9;
  --surface2: #ECEAE2;
  --border:   #D6D2C8;
  --border2:  #B4B0A6;
  --text:     #1A1714;
  --text2:    #3E3A34;
  --text3:    #706860;
  --text4:    #908880;
  --text5:    #B0A898;
  --accent:   #9B2335;
  --strip:    #ECEAE2;
  --impact:   #F5F4EF;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       font-weight: 400; margin: 0; padding: 0; color: var(--text); }
.bg  { background: var(--bg); padding: 32px 16px; }
.wrap { max-width: 600px; margin: 0 auto; }

/* Masthead */
.masthead { text-align: center; padding: 36px 0 28px;
            border-bottom: 1px solid var(--border); }
.masthead-name { font-family: 'Instrument Serif', Georgia, 'Times New Roman', serif;
                  font-size: 24px; font-style: italic; color: var(--text); }
.masthead-name em { color: var(--accent); font-style: normal; font-weight: 400; }
.masthead-sub { font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
                color: var(--text4); margin-top: 6px; font-weight: 500; }

/* Header */
.hd { padding: 32px 40px 24px; }
.hd-eye { font-size: 10px; color: var(--text4); letter-spacing: 1px;
           text-transform: uppercase; margin-bottom: 14px; font-weight: 500; }
.hd-dot { width: 5px; height: 5px; background: var(--accent);
           border-radius: 50%; display: inline-block;
           margin-right: 6px; vertical-align: middle; }
.hd-title { font-family: 'Instrument Serif', Georgia, 'Times New Roman', serif;
             font-size: 28px; font-weight: 400; color: var(--text);
             line-height: 1.2; margin-bottom: 4px; }
.hd-title em { font-style: italic; color: var(--text2); }
.hd-stats { font-size: 11px; color: var(--text4); letter-spacing: 0.2px; margin-top: 16px; }
.hd-stats .n   { color: var(--text2); font-weight: 500; }
.hd-stats .sep { color: var(--border2); margin: 0 8px; }

/* Édito */
.edito { padding: 0 40px 26px; }
.edito p { font-size: 13px; color: var(--text3); line-height: 1.85; }
.edito-sign { font-size: 11px; color: var(--text4); margin-top: 12px;
               letter-spacing: .5px; font-weight: 500; }

/* CTA portal */
.portal-strip { background: var(--strip); border-top: 1px solid var(--border);
                border-bottom: 1px solid var(--border);
                padding: 18px 40px; margin-bottom: 8px; }
.portal-strip p { font-size: 12px; color: var(--text4);
                  letter-spacing: .2px; line-height: 1.6;
                  display: inline-block; vertical-align: middle;
                  max-width: 340px; }
.portal-btn { font-size: 12px; font-weight: 500; color: var(--text);
              text-decoration: none; background: var(--surface);
              border: 1px solid var(--border2);
              padding: 8px 18px; border-radius: 4px;
              white-space: nowrap; display: inline-block;
              vertical-align: middle; margin-left: 16px; }

/* Section headers */
.grp { padding: 28px 40px 12px; }
.grp-label { font-size: 11px; font-weight: 500;
              letter-spacing: .6px; text-transform: uppercase;
              padding-left: 10px; }
.grp-reg   { color: #3B52A4; border-left: 3px solid #3B52A4; }
.grp-reco  { color: #1A6B5C; border-left: 3px solid #1A6B5C; }
.grp-innov { color: #9B5714; border-left: 3px solid #9B5714; }

/* Cards articles */
.card { background: var(--surface); border: 1px solid var(--border);
         border-radius: 4px; padding: 22px 28px 20px;
         margin: 0 40px 8px; }
.card-top { margin-bottom: 10px; }
.card-top > * { display: inline-block; vertical-align: middle; margin-right: 7px; }
.card-date { font-size: 11px; color: var(--text5); }

/* Catégories */
.cat { font-size: 10px; letter-spacing: .3px; text-transform: uppercase;
        padding: 2px 8px; border-radius: 2px; font-weight: 500; }
.cat-reglementation { background: rgba(59,82,164,.07); color: #3B52A4;
                      border: 0.5px solid rgba(59,82,164,.2); }
.cat-recommandation { background: rgba(26,107,92,.07); color: #1A6B5C;
                      border: 0.5px solid rgba(26,107,92,.2); }
.cat-innovation     { background: rgba(155,87,20,.07); color: #9B5714;
                      border: 0.5px solid rgba(155,87,20,.2); }

.card-title { font-size: 0.95rem; font-weight: 500; color: var(--text);
               line-height: 1.45; margin-bottom: 10px; }
.card-resume { font-size: 13px; font-weight: 400; color: var(--text3);
                line-height: 1.7; margin-bottom: 12px; }
.card-impact { font-size: 12px; color: var(--text3); line-height: 1.65;
                padding: 10px 14px; margin-bottom: 14px;
                background: var(--impact); border-radius: 4px;
                font-weight: 400; border: 1px solid var(--border); }
.card-link { font-size: 12px; font-weight: 500; color: var(--accent);
              text-decoration: none;
              display: inline-block; }

/* Footer */
.footer { padding: 24px 0 8px; text-align: center; }
.footer p { font-size: 11px; color: var(--text5); letter-spacing: .2px; line-height: 2; }
.footer a { color: var(--text4); text-decoration: none; }

/* ── Responsive mobile ── */
@media (max-width: 480px) {
  .bg  { padding: 16px 8px; }
  .hd  { padding: 20px 16px 16px; }
  .hd-title { font-size: 20px; }
  .edito { padding: 0 16px 20px; }
  .portal-strip { padding: 14px 16px; }
  .portal-strip p { display: block; max-width: 100%; margin-right: 0; }
  .portal-btn { display: block; margin-left: 0; margin-top: 10px; text-align: center; }
  .grp  { padding: 20px 16px 8px; }
  .card { margin: 0 8px 8px; padding: 16px 14px 14px; }
  .card-title { font-size: 0.88rem; }
  .card-resume { font-size: 12px; }
}
"""

# ---------------------------------------------------------------------------
# Rendu d'un article
# ---------------------------------------------------------------------------

def _render_article(item: dict[str, Any], featured: bool = False) -> str:
    tri = item.get("tri_json") or {}
    score = item.get("score_density") or 5
    prio_label, prio_class = _priority_label(score)

    date_str = _format_date(item.get("official_date") or "")

    # Catégorie : on remonte source_type en priorité pour les articles innovation/presse
    source_type = item.get("source_type") or ""
    cat = item.get("categorie") or ""
    # Mapper source_type → cat si pas de catégorie explicite
    if not cat and source_type in CAT_STYLES:
        cat = source_type
    cat_label, cat_class = CAT_STYLES.get(cat, ("", ""))

    titre = tri.get("titre_court") or item.get("title_raw") or ""
    resume = tri.get("resume") or ""
    impact = tri.get("impact_pratique") or ""
    url = _safe_url(item.get("official_url") or "#")

    # CTA dynamique selon source_type
    cta_text = _SOURCE_TYPE_CTA.get(source_type, "Lire l'article →")

    cat_html = (
        f'<span class="cat {cat_class}">{_he(cat_label)}</span>'
        if cat_label else ""
    )

    impact_html = (
        f'<div class="card-impact">{_he(impact)}</div>'
        if impact else ""
    )

    return f"""
<div class="card">
  <div class="card-top">
    <span class="card-date">{_he(date_str)}</span>
    {cat_html}
  </div>
  <div class="card-title">{_he(titre)}</div>
  <p class="card-resume">{_he(resume)}</p>
  {impact_html}
  <a class="card-link" href="{url}">{cta_text}</a>
</div>
"""


# ---------------------------------------------------------------------------
# Génération de l'édito
# ---------------------------------------------------------------------------

def _generate_edito(
    items_spec: list,
    items_transv: list,
    specialty_name: str,
    emission_date: date,
) -> str:
    n_total = len(items_spec) + len(items_transv)
    mois = MOIS_FR_LONG[emission_date.month]

    return (
        f"Réglementation, recommandations cliniques, innovation\u00a0: "
        f"chaque semaine, MedNews sélectionne pour votre spécialité "
        f"les publications à fort impact pratique. "
        f"Cette édition regroupe {n_total}\u00a0article{'s' if n_total > 1 else ''} "
        f"issus des parutions de {mois}\u00a0{emission_date.year} et du mois précédent, "
        f"classés par dimension et par pertinence clinique."
    )


# ---------------------------------------------------------------------------
# Texte plain
# ---------------------------------------------------------------------------

def _build_plain(
    specialty_name: str,
    items_spec: list,
    items_transv: list,
    portal_url: str,
) -> str:
    lines = [
        f"MedNews — La revue médicale · {specialty_name}",
        "=" * 50,
        "",
    ]
    for item in items_spec + items_transv:
        tri = item.get("tri_json") or {}
        titre = tri.get("titre_court") or item.get("title_raw") or ""
        impact = tri.get("impact_pratique") or ""
        url = item.get("official_url") or ""
        lines += [f"• {titre}", f"  {impact}", f"  {url}", ""]
    lines += ["---", f"Accéder à mon espace : {portal_url}"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def _source_tags(items: list[dict]) -> str:
    """Génère les tags de sources à partir des items (ex: PubMed · TCTMD · ESVS)."""
    seen: list[str] = []
    _source_map = {
        "pubmed_jvs":          "JVS",
        "pubmed_ejves":        "EJVES",
        "pubmed_jet":          "J Endovasc Ther",
        "pubmed_ann_vasc_surg":"Ann Vasc Surg",
        "pubmed_":             "PubMed",
        "vascular_specialist": "Vascular Specialist",
        "vascular_news":       "Vascular News",
        "tctmd":               "TCTMD",
        "linc_highlights":     "LINC",
        "cirse_highlights":    "CIRSE",
        "esvs_highlights":     "ESVS",
        "quotidien_medecin":   "Quotidien du Médecin",
        "egora":               "Egora",
        "has_":                "HAS",
        "ansm_":               "ANSM",
        "legifrance":          "JORF",
        "fda_":                "FDA",
        "eudamed":             "CE/EUDAMED",
    }
    for item in items:
        src = item.get("source") or ""
        label = None
        for prefix, lbl in _source_map.items():
            if src == prefix or src.startswith(prefix):
                label = lbl
                break
        if label and label not in seen:
            seen.append(label)
    return " · ".join(seen[:5]) if seen else "PubMed · Presse médicale"


def _classify_section(item: dict) -> str:
    """Classifie un article dans l'une des 3 dimensions éditoriales."""
    cat = (item.get("categorie") or "").lower()
    source_type = (item.get("source_type") or "").lower()
    source = (item.get("source") or "").lower()

    if cat in ("reglementation", "exercice") or source_type in ("regulatory", "reglementation"):
        return "reglementation"
    if cat in ("recommandation", "clinique") or source_type in ("guideline", "recommandation"):
        return "recommandations"
    if cat in ("therapeutique", "innovation") or source_type in (
        "innovation", "journal", "press", "presse", "congress", "device"
    ):
        return "innovation"
    # Fallback par source
    if source.startswith("legifrance") or source.startswith("ansm_"):
        return "reglementation"
    if source.startswith("has_"):
        return "recommandations"
    return "innovation"


def build_newsletter(
    specialty_slug: str,
    items: list[dict[str, Any]],
    emission_date: date | None = None,
    portal_url: str = "",
    unsubscribe_url: str = "{{unsubscribe_url}}",
    archive_url: str = "{{archive_url}}",
    max_articles: int = 6,
) -> tuple[str, str, str]:
    """
    Construit la newsletter.

    Args:
        specialty_slug  : slug de la spécialité
        items           : liste d'items APPROVED (spécialité + transversaux)
        emission_date   : date d'émission (défaut: aujourd'hui)
        portal_url      : URL du portal (construit depuis BASE_URL si vide)
        unsubscribe_url : URL de désabonnement
        archive_url     : URL d'archive
        max_articles    : nombre maximum d'articles dans la newsletter (défaut 6)

    Returns:
        (sujet: str, html: str, texte_plain: str)
    """
    if emission_date is None:
        emission_date = date.today()

    base = os.environ.get("BASE_URL", "").rstrip("/")
    if not portal_url:
        portal_url = f"{base}/portal" if base else "#"
    if unsubscribe_url == "{{unsubscribe_url}}":
        unsubscribe_url = f"{base}/settings" if base else "#"
    if archive_url == "{{archive_url}}":
        archive_url = f"{base}/portal" if base else "#"

    specialty_name = SPECIALTY_LABELS.get(specialty_slug, specialty_slug) or "Médecine"
    mois_annee = f"{MOIS_FR_LONG[emission_date.month].capitalize()} {emission_date.year}"

    # Fenêtre : mois en cours + mois précédent
    if emission_date.month == 1:
        prev_year, prev_month = emission_date.year - 1, 12
    else:
        prev_year, prev_month = emission_date.year, emission_date.month - 1

    def _in_window(item: dict) -> bool:
        raw = item.get("official_date") or ""
        try:
            d = date.fromisoformat(raw[:10])
            return (d.year == emission_date.year and d.month == emission_date.month) or \
                   (d.year == prev_year and d.month == prev_month)
        except Exception:
            return True  # date manquante → on garde

    items = [i for i in items if _in_window(i)]

    # Filtrer par spécialité
    items_spec = [
        i for i in items
        if specialty_slug in (i.get("specialites") or [])
        or i.get("specialty_slug") == specialty_slug
    ]

    # Trier par score descendant, puis garder les N meilleurs
    items_spec = sorted(items_spec, key=lambda x: x.get("score_density") or 0, reverse=True)
    items_spec = items_spec[:max_articles]

    n_total = len(items_spec)

    # Classer en 3 sections
    items_reg   = sorted([i for i in items_spec if _classify_section(i) == "reglementation"],
                         key=lambda x: x.get("score_density") or 0, reverse=True)
    items_reco  = sorted([i for i in items_spec if _classify_section(i) == "recommandations"],
                         key=lambda x: x.get("score_density") or 0, reverse=True)
    items_innov = sorted([i for i in items_spec if _classify_section(i) == "innovation"],
                         key=lambda x: x.get("score_density") or 0, reverse=True)
    n_reg   = len(items_reg)
    n_reco  = len(items_reco)
    n_innov = len(items_innov)

    # Sujet : accroche sur l'item le plus urgent
    top_item = items_spec[0] if items_spec else None
    if top_item:
        top_titre = (top_item.get("tri_json") or {}).get("titre_court") or top_item.get("title_raw") or ""
        if len(top_titre) > 52:
            top_titre = top_titre[:50].rsplit(" ", 1)[0] + "…"
        sujet = f"[MedNews] {top_titre} · {n_total} sélection{'s' if n_total > 1 else ''} {specialty_name}"
    else:
        sujet = f"[MedNews] {specialty_name} — Veille {MOIS_FR_LONG[emission_date.month]} {emission_date.year}"

    edito_text = _generate_edito(items_spec, [], specialty_name, emission_date)

    source_tags = _source_tags(items_spec)

    def _section_html(label: str, css: str, items: list) -> str:
        if not items:
            return ""
        cards = "".join(_render_article(i) for i in items)
        return f'<div class="grp"><div class="grp-label {css}">{_he(label)}</div></div>\n{cards}'

    articles_html = (
        _section_html("Réglementation", "grp-reg", items_reg)
        + _section_html("Recommandations cliniques", "grp-reco", items_reco)
        + _section_html("Innovation", "grp-innov", items_innov)
    )
    if not articles_html.strip():
        articles_html = '<p style="color:var(--text5);font-style:italic;padding:20px 40px;">Aucun article sélectionné cette semaine.</p>'

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_he(sujet)}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500&family=Instrument+Serif:ital@0;1&display=swap">
<style>{_CSS}</style>
</head>
<body>
<div class="bg">
<div class="wrap">

  <!-- MASTHEAD -->
  <div class="masthead">
    <div class="masthead-name">Med<em>News</em></div>
    <div class="masthead-sub">La revue médicale · {_he(specialty_name)}</div>
  </div>

  <!-- HEADER -->
  <div class="hd">
    <div class="hd-eye">
      <span class="hd-dot"></span>Sélection éditoriale
    </div>
    <div class="hd-title">
      {_he(specialty_name)}<br><em>{_he(mois_annee)}</em>
    </div>
    <div class="hd-stats">
      <span class="n">{n_reg}</span> réglementaire{'s' if n_reg != 1 else ''}
      <span class="sep">·</span>
      <span class="n">{n_reco}</span> recommandation{'s' if n_reco != 1 else ''}
      <span class="sep">·</span>
      <span class="n">{n_innov}</span> innovation{'s' if n_innov != 1 else ''}
      <span class="sep">·</span>{_he(source_tags)}
    </div>
  </div>

  <!-- ÉDITO -->
  <div class="edito">
    <p>{_he(edito_text)}</p>
    <div class="edito-sign">— L'équipe MedNews</div>
  </div>

  <!-- CTA PORTAL -->
  <div class="portal-strip">
    <p>Retrouvez tous vos articles,<br>archives et favoris sur votre espace</p>
    <a class="portal-btn" href="{_safe_url(portal_url)}">Accéder à mon espace →</a>
  </div>

  <!-- ARTICLES -->
  {articles_html}

  <!-- FOOTER -->
  <div class="footer">
    <p>
      Abonné à MedNews ·
      <a href="{_safe_url(unsubscribe_url)}">Se désabonner</a> ·
      <a href="{_safe_url(archive_url)}">Voir en ligne</a><br>
      MedNews — Veille médicale pour spécialistes
    </p>
  </div>

</div>
</div>
</body>
</html>"""

    plain = _build_plain(specialty_name, items_spec, [], portal_url)

    return sujet, html, plain
