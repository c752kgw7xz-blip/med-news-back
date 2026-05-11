# app/newsletter_builder.py
"""
Construit le HTML de la newsletter pour une spécialité donnée.

Entrée  : liste d'items APPROVED pour cette spécialité (depuis DB)
Sortie  : (sujet_email: str, html: str, texte_plain: str)

Design :
  - Reprend exactement le système de design du portail (Outfit + Instrument Serif,
    palette warm-gray, bordures gauche colorées par dimension éditoriale)
  - Chaque article = carte avec bordure colorée, titre, résumé, impact, points clés, lien
  - Ordre : score_density DESC (les plus importants en premier)
  - Sections : Réglementation (bleu #3B52A4) · Recommandations (vert #1A6B5C) · Innovation (ambre #9B5714)
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
    "medecine-generale":    "Médecine générale",
    "cardiologie":          "Cardiologie",
    "dermatologie":         "Dermatologie",
    "endocrinologie":       "Endocrinologie",
    "gastro-enterologie":   "Gastro-entérologie",
    "gynecologie":          "Gynécologie",
    "neurologie":           "Neurologie",
    "ophtalmologie":        "Ophtalmologie",
    "orl":                  "ORL",
    "pediatrie":            "Pédiatrie",
    "pneumologie":          "Pneumologie",
    "psychiatrie":          "Psychiatrie",
    "rhumatologie":         "Rhumatologie",
    "urologie":             "Urologie",
    "medecine-interne":     "Médecine interne",
    "medecine-urgences":    "Médecine d'urgences",
    "geriatrie":            "Gériatrie",
    "medecine-physique":    "Médecine physique et réadaptation",
    "oncologie":            "Oncologie",
    "hematologie":          "Hématologie",
    "infectiologie":        "Infectiologie",
    "nephrologie":          "Néphrologie",
    "radiologie":           "Radiologie",
    "anesthesiologie":      "Anesthésiologie",
    "chirurgie":            "Chirurgie",
    "chirurgie-vasculaire": "Chirurgie vasculaire",
    "chirurgie-orthopedique":"Chirurgie orthopédique",
    "chirurgie-thoracique": "Chirurgie thoracique",
    "chirurgie-plastique":  "Chirurgie plastique",
    "neurochirurgie":       "Neurochirurgie",
    "chirurgie-pediatrique":"Chirurgie pédiatrique",
    "chirurgie-cardiaque":  "Chirurgie cardiaque",
    "infirmiers":           "Infirmiers",
    "kinesitherapie":       "Kinésithérapie",
    "sage-femme":           "Sage-femme",
    "biologiste":           "Biologie médicale",
    "dentiste":             "Dentisterie",
    "orthodontiste":        "Orthodontie",
    "pharmacien":           "Pharmacien d'officine",
}

# ---------------------------------------------------------------------------
# Couleurs par dimension éditoriale — identiques au portail
# ---------------------------------------------------------------------------

_SECTION_COLORS: dict[str, dict] = {
    "reglementation": {
        "border":  "#3B52A4",
        "border_faint": "rgba(59,82,164,.22)",
        "cat_bg":  "rgba(59,82,164,.07)",
        "cat_fg":  "#3B52A4",
        "cat_bd":  "rgba(59,82,164,.18)",
        "label":   "Réglementation",
        "grp_css": "grp-reg",
    },
    "recommandations": {
        "border":  "#1A6B5C",
        "border_faint": "rgba(26,107,92,.22)",
        "cat_bg":  "rgba(26,107,92,.07)",
        "cat_fg":  "#1A6B5C",
        "cat_bd":  "rgba(26,107,92,.18)",
        "label":   "Recommandations cliniques",
        "grp_css": "grp-reco",
    },
    "innovation": {
        "border":  "#9B5714",
        "border_faint": "rgba(155,87,20,.22)",
        "cat_bg":  "rgba(155,87,20,.07)",
        "cat_fg":  "#9B5714",
        "cat_bd":  "rgba(155,87,20,.18)",
        "label":   "Innovation",
        "grp_css": "grp-innov",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_url(url: str) -> str:
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
    try:
        d = date.fromisoformat(date_raw[:10])
        return f"{d.day} {MOIS_FR[d.month]} {d.year}"
    except Exception:
        return date_raw or ""


# ---------------------------------------------------------------------------
# CSS — palette exacte du portail, thème adaptatif OS
# ---------------------------------------------------------------------------

_CSS = """
/* ── Thème sombre (Apple Mail, iOS Mail) ── */
@media (prefers-color-scheme: dark) {
  :root {
    --bg:       #17140C;
    --surface:  #1E1B12;
    --surface2: #252219;
    --border:   #342F24;
    --border2:  #4A4438;
    --text:     #EDE7DC;
    --text2:    #C6BEB4;
    --text3:    #A8A098;
    --text4:    #8A8378;
    --text5:    #6A6360;
    --accent:   #9B2335;
    --strip:    #1E1B12;
  }
}
/* ── Thème clair (défaut, Gmail, Outlook) ── */
:root {
  --bg:       #F5F4EF;
  --surface:  #FDFCF9;
  --surface2: #ECEAE2;
  --border:   #D6D2C8;
  --border2:  #B4B0A6;
  --text:     #1A1714;
  --text2:    #3E3A34;
  --text3:    #4E4840;
  --text4:    #6A6258;
  --text5:    #908880;
  --accent:   #9B2335;
  --strip:    #ECEAE2;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  font-weight: 400; color: var(--text);
}
.bg  { background: var(--bg); padding: 32px 16px; }
.wrap { max-width: 600px; margin: 0 auto; }

/* ── Masthead ── */
.masthead {
  text-align: center; padding: 36px 0 28px;
  border-bottom: 1px solid var(--border);
}
.masthead-name {
  font-family: 'Instrument Serif', Georgia, 'Times New Roman', serif;
  font-size: 24px; font-style: italic; color: var(--text); letter-spacing: -.3px;
}
.masthead-name em { color: var(--accent); font-style: normal; }
.masthead-sub {
  font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--text4); margin-top: 6px; font-weight: 500;
}

/* ── Header ── */
.hd { padding: 32px 40px 24px; }
.hd-eye {
  font-size: 10px; color: var(--text4); letter-spacing: 1px;
  text-transform: uppercase; margin-bottom: 14px; font-weight: 500;
}
.hd-dot {
  width: 5px; height: 5px; background: var(--accent);
  border-radius: 50%; display: inline-block;
  margin-right: 6px; vertical-align: middle;
}
.hd-title {
  font-family: 'Instrument Serif', Georgia, 'Times New Roman', serif;
  font-size: 28px; font-weight: 400; color: var(--text);
  line-height: 1.2; margin-bottom: 4px;
}
.hd-title em { font-style: italic; color: var(--text2); }
.hd-stats { font-size: 11px; color: var(--text4); letter-spacing: .2px; margin-top: 16px; }
.hd-stats .n   { color: var(--text2); font-weight: 500; }
.hd-stats .sep { color: var(--border2); margin: 0 8px; }

/* ── Édito ── */
.edito { padding: 0 40px 26px; }
.edito p { font-size: 13px; color: var(--text3); line-height: 1.85; }
.edito-sign { font-size: 11px; color: var(--text4); margin-top: 12px; letter-spacing: .5px; font-weight: 500; }

/* ── CTA portal ── */
.portal-strip {
  background: var(--strip); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);
  padding: 18px 40px; margin-bottom: 8px;
}
.portal-strip p {
  font-size: 12px; color: var(--text4); letter-spacing: .2px; line-height: 1.6;
  display: inline-block; vertical-align: middle; max-width: 320px;
}
.portal-btn {
  font-size: 12px; font-weight: 500; color: var(--text2);
  text-decoration: none; background: var(--surface);
  border: 1px solid var(--border2);
  padding: 8px 18px; border-radius: 4px;
  white-space: nowrap; display: inline-block;
  vertical-align: middle; margin-left: 16px;
}

/* ── Section headers ── */
.grp { padding: 28px 40px 12px; }
.grp-label {
  font-size: 10px; font-weight: 600; letter-spacing: .6px; text-transform: uppercase;
  padding-left: 10px; display: inline-block;
}
.grp-reg   { color: #3B52A4; border-left: 3px solid #3B52A4; }
.grp-reco  { color: #1A6B5C; border-left: 3px solid #1A6B5C; }
.grp-innov { color: #9B5714; border-left: 3px solid #9B5714; }

/* ── Article cards — structure portail ── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 18px 22px 16px;
  margin: 0 40px 8px;
  border-left: 3px solid var(--border);
}
.card-top {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 8px; flex-wrap: nowrap;
}
.card-date { font-size: 11px; color: var(--text5); flex-shrink: 0; }

/* Badges catégorie */
.cat {
  font-size: 10px; letter-spacing: .2px; text-transform: uppercase;
  padding: 2px 7px; border-radius: 2px; font-weight: 500;
  border: 0.5px solid transparent;
}
.cat-reg   { background: rgba(59,82,164,.07); color: #3B52A4; border-color: rgba(59,82,164,.18); }
.cat-reco  { background: rgba(26,107,92,.07); color: #1A6B5C; border-color: rgba(26,107,92,.18); }
.cat-innov { background: rgba(155,87,20,.07); color: #9B5714; border-color: rgba(155,87,20,.18); }

/* Titre */
.card-title {
  font-size: 15px; font-weight: 500; color: var(--text);
  line-height: 1.4; margin-bottom: 8px;
}

/* Résumé */
.card-resume {
  font-size: 13px; font-weight: 400; color: var(--text3);
  line-height: 1.7; margin-bottom: 10px;
}

/* Impact pratique — style italic + border-left (identique portail) */
.card-impact {
  font-size: 13px; color: var(--text2); font-style: italic; line-height: 1.6;
  padding-left: 10px; margin-bottom: 12px;
  border-left: 2px solid var(--border);
}

/* Points clés */
.card-points {
  margin: 0 0 12px 0; padding: 0; list-style: none;
}
.card-points li {
  font-size: 12px; color: var(--text3); line-height: 1.55;
  padding-left: 14px; position: relative; margin-bottom: 4px;
}
.card-points li::before {
  content: "·"; position: absolute; left: 0;
  color: var(--text4); font-size: 14px; line-height: 1.3;
}

/* Bouton lien officiel — style .btn-official du portail */
.card-link {
  display: inline-block;
  font-size: 12px; font-weight: 500; color: var(--text2);
  text-decoration: none;
  border: 1px solid var(--border2);
  border-radius: 4px; padding: 6px 14px;
  background: transparent;
}

/* ── Footer ── */
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
  .card { margin: 0 8px 8px; padding: 14px 14px 12px; }
  .card-title { font-size: 14px; }
  .card-resume { font-size: 12px; }
  .card-top { flex-wrap: wrap; }
}
"""

# ---------------------------------------------------------------------------
# Classification éditoriale
# ---------------------------------------------------------------------------

def _classify_section(item: dict) -> str:
    """Détermine la section newsletter d'un item.

    Priorité 1 : source_type (déterministe pour les sources institutionnelles,
                  LLM pour les journaux/sociétés savantes)
    Priorité 2 : categorie (clinique/therapeutique/exercice — filtre portail)
    Priorité 3 : motif sur le slug source (fallback ultime)
    """
    source_type = (item.get("source_type") or "").lower()
    cat = (item.get("categorie") or "").lower()
    source = (item.get("source") or "").lower()

    # Source_type → section newsletter (valeurs valides : reglementaire | recommandation | innovation)
    if source_type == "reglementaire":
        return "reglementation"
    if source_type == "recommandation":
        return "recommandations"
    if source_type == "innovation":
        return "innovation"

    # Fallback categorie (clinique/therapeutique/exercice)
    if cat == "exercice":
        return "reglementation"
    if cat == "clinique":
        return "recommandations"
    if cat == "therapeutique":
        return "innovation"

    # Fallback ultime : pattern sur le slug
    if source.startswith("legifrance") or source.startswith("ansm_") or source.startswith("piste_"):
        return "reglementation"
    if source.startswith("has_") or source.startswith("sf") or source.endswith("_guidelines"):
        return "recommandations"
    return "innovation"


# ---------------------------------------------------------------------------
# Rendu d'un article
# ---------------------------------------------------------------------------

def _render_article(item: dict[str, Any], section: str) -> str:
    tri     = item.get("tri_json") or {}
    lecture = item.get("lecture_json") or {}
    sc      = _SECTION_COLORS.get(section, _SECTION_COLORS["innovation"])

    date_str = _format_date(item.get("official_date") or "")
    titre    = tri.get("titre_court") or item.get("title_raw") or ""
    resume   = tri.get("resume") or ""
    impact   = tri.get("impact_pratique") or ""
    url      = _safe_url(item.get("official_url") or "#")

    # Points clés (max 3 — au-delà ça alourdit l'email)
    points = lecture.get("points_cles") or []
    if isinstance(points, list):
        points = [p for p in points if isinstance(p, str) and p.strip()][:3]

    # Badge catégorie
    cat_css_map = {"reglementation": "cat-reg", "recommandations": "cat-reco", "innovation": "cat-innov"}
    cat_css   = cat_css_map.get(section, "cat-innov")
    cat_label = sc["label"]

    # CTA
    cta_map = {
        "reglementation":  "Lire le texte officiel →",
        "recommandations": "Lire la recommandation →",
        "innovation":      "Lire l'étude →",
    }
    cta_text = cta_map.get(section, "Lire l'article →")

    # Impact HTML
    impact_html = (
        f'<div class="card-impact">{_he(impact)}</div>'
        if impact else ""
    )

    # Points clés HTML
    points_html = ""
    if points:
        items_li = "".join(f"<li>{_he(p)}</li>" for p in points)
        points_html = f'<ul class="card-points">{items_li}</ul>'

    # Bouton lien
    link_html = (
        f'<a class="card-link" href="{url}">{cta_text}</a>'
        if url != "#" else ""
    )

    # Bordure gauche colorée (inline pour fiabilité email)
    border_style = (
        f'border-left: 3px solid {sc["border"]}; '
        f'border-color: {sc["border_faint"]}; '
        f'border-left-color: {sc["border"]}; '
    )

    return f"""
<div class="card" style="{border_style}">
  <div class="card-top">
    <span class="card-date">{_he(date_str)}</span>
    <span class="cat {cat_css}">{_he(cat_label)}</span>
  </div>
  <div class="card-title">{_he(titre)}</div>
  <p class="card-resume">{_he(resume)}</p>
  {impact_html}{points_html}{link_html}
</div>
"""


# ---------------------------------------------------------------------------
# Source tags
# ---------------------------------------------------------------------------

_SOURCE_MAP = {
    "pubmed_jvs":          "JVS",
    "pubmed_ejves":        "EJVES",
    "pubmed_jet":          "J Endovasc Ther",
    "pubmed_ann_vasc_surg":"Ann Vasc Surg",
    "pubmed_":             "PubMed",
    "vascular_specialist": "Vascular Specialist",
    "vascular_news":       "Vascular News",
    "tctmd":               "TCTMD",
    "has_":                "HAS",
    "ansm_":               "ANSM",
    "legifrance":          "JORF",
    "piste_kali":          "UNCAM/KALI",
    "fda_":                "FDA",
    "eudamed":             "CE/EUDAMED",
    "ema_":                "EMA",
    "ecdc_":               "ECDC",
}


def _source_tags(items: list[dict]) -> str:
    seen: list[str] = []
    for item in items:
        src = item.get("source") or ""
        label = None
        for prefix, lbl in _SOURCE_MAP.items():
            if src == prefix or src.startswith(prefix):
                label = lbl
                break
        if label and label not in seen:
            seen.append(label)
    return " · ".join(seen[:5]) if seen else "PubMed · Presse médicale"


# ---------------------------------------------------------------------------
# Édito
# ---------------------------------------------------------------------------

def _generate_edito(n_total: int, specialty_name: str, emission_date: date) -> str:
    mois = MOIS_FR_LONG[emission_date.month]
    return (
        f"Réglementation, recommandations cliniques, innovation : "
        f"MedNews sélectionne chaque mois pour votre spécialité "
        f"les publications à fort impact pratique. "
        f"Cette édition regroupe {n_total} article{'s' if n_total > 1 else ''} "
        f"issus des parutions de {mois} {emission_date.year} et du mois précédent, "
        f"classés par dimension et par pertinence clinique."
    )


# ---------------------------------------------------------------------------
# Texte plain
# ---------------------------------------------------------------------------

def _build_plain(specialty_name: str, items: list[dict], portal_url: str) -> str:
    lines = [
        f"MedNews — La revue médicale · {specialty_name}",
        "=" * 50,
        "",
    ]
    for item in items:
        tri    = item.get("tri_json") or {}
        titre  = tri.get("titre_court") or item.get("title_raw") or ""
        impact = tri.get("impact_pratique") or ""
        url    = item.get("official_url") or ""
        lines += [f"• {titre}", f"  {impact}", f"  {url}", ""]
    lines += ["---", f"Accéder à mon espace : {portal_url}"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

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
            return (
                (d.year == emission_date.year and d.month == emission_date.month) or
                (d.year == prev_year and d.month == prev_month)
            )
        except Exception:
            return True

    items = [i for i in items if _in_window(i)]

    # Filtrer par spécialité
    items_spec = [
        i for i in items
        if specialty_slug in (i.get("specialites") or [])
        or i.get("specialty_slug") == specialty_slug
    ]

    # Trier par score, limiter
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

    # Sujet email
    top_item = items_spec[0] if items_spec else None
    if top_item:
        top_titre = (top_item.get("tri_json") or {}).get("titre_court") or top_item.get("title_raw") or ""
        if len(top_titre) > 52:
            top_titre = top_titre[:50].rsplit(" ", 1)[0] + "…"
        sujet = f"[MedNews] {top_titre} · {n_total} sélection{'s' if n_total > 1 else ''} {specialty_name}"
    else:
        sujet = f"[MedNews] {specialty_name} — Veille {MOIS_FR_LONG[emission_date.month]} {emission_date.year}"

    edito_text  = _generate_edito(n_total, specialty_name, emission_date)
    source_tags = _source_tags(items_spec)

    def _section_html(section: str, items: list) -> str:
        if not items:
            return ""
        sc    = _SECTION_COLORS[section]
        cards = "".join(_render_article(i, section) for i in items)
        return (
            f'<div class="grp">'
            f'<div class="grp-label {sc["grp_css"]}">{_he(sc["label"])}</div>'
            f'</div>\n{cards}'
        )

    articles_html = (
        _section_html("reglementation", items_reg)
        + _section_html("recommandations", items_reco)
        + _section_html("innovation", items_innov)
    )
    if not articles_html.strip():
        articles_html = (
            '<p style="color:var(--text5);font-style:italic;padding:20px 40px;">'
            'Aucun article sélectionné cette période.</p>'
        )

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_he(sujet)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Outfit:wght@400;500&display=swap" rel="stylesheet">
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

    plain = _build_plain(specialty_name, items_spec, portal_url)
    return sujet, html, plain
