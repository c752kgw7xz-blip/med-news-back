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
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    "therapeutique": ("Médicaments & Dispositifs", "cat-therapeutique"),
    "clinique":      ("Clinique",                  "cat-clinique"),
    "exercice":      ("Exercice & Admin",           "cat-exercice"),
}

# ---------------------------------------------------------------------------
# CSS complet (thème adaptatif OS)
# ---------------------------------------------------------------------------

_CSS = """
@media (prefers-color-scheme: dark) {
  :root {
    --bg:       #08090e;
    --surface:  #0d0e16;
    --surface2: #11121c;
    --border:   #1c1e30;
    --border2:  #252840;
    --text:     #e8e9f4;
    --text2:    #c8c8d4;
    --text3:    #8b8fa8;
    --text4:    #6b6f88;
    --text5:    #4a4e68;
    --green:    #1f9478;
    --strip:    #11121c;
    --impact:   #11121c;
  }
}
:root {
  --bg:       #f6f5f2;
  --surface:  #ffffff;
  --surface2: #f0ede8;
  --border:   #e4e0d8;
  --border2:  #cac4bb;
  --text:     #1a1814;
  --text2:    #4a4540;
  --text3:    #7a7268;
  --text4:    #9a9288;
  --text5:    #bcb6ac;
  --green:    #1f9478;
  --strip:    #f0ede8;
  --impact:   #f6f5f2;
}
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500&family=Instrument+Serif:ital@0;1&family=DM+Mono:wght@400&display=swap');
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); font-family: 'Outfit', sans-serif;
       font-weight: 300; margin: 0; padding: 0; color: var(--text); }
.bg  { background: var(--bg); padding: 32px 16px; }
.wrap { max-width: 600px; margin: 0 auto; }

/* Masthead */
.masthead { text-align: center; padding: 36px 0 28px;
            border-bottom: 1px solid var(--border); }
.masthead-name { font-family: 'Instrument Serif', Georgia, serif;
                  font-size: 24px; font-style: italic; color: var(--text); }
.masthead-name em { color: var(--green); font-style: italic; }
.masthead-sub { font-family: 'DM Mono', monospace; font-size: 9px;
                letter-spacing: 3px; text-transform: uppercase;
                color: var(--text5); margin-top: 6px; }

/* Header */
.hd { background: transparent; border: none;
      border-radius: 0; padding: 32px 40px 28px; }
.hd-eye { font-family: 'DM Mono', monospace; font-size: 10px;
           color: var(--text5); letter-spacing: 2px;
           text-transform: uppercase; margin-bottom: 14px; }
.hd-dot { width: 6px; height: 6px; background: var(--green);
           border-radius: 50%; display: inline-block;
           margin-right: 6px; vertical-align: middle; }
.hd-title { font-family: 'Instrument Serif', Georgia, serif;
             font-size: 28px; font-weight: 400; color: var(--text);
             line-height: 1.2; margin-bottom: 4px; }
.hd-title em { font-style: italic; color: var(--green); }
.hd-stats { font-family: 'DM Mono', monospace; font-size: 10px;
             color: var(--text4); letter-spacing: 0.3px; margin-top: 16px; }
.hd-stats .n   { color: var(--text2); }
.hd-stats .sep { color: var(--border2); margin: 0 8px; }

/* Édito */
.edito { background: transparent; border: none;
          padding: 24px 40px 26px; }
.edito p { font-size: 13px; color: var(--text3); line-height: 1.85; }
.edito-sign { font-family: 'DM Mono', monospace; font-size: 10px;
               color: var(--text5); margin-top: 12px;
               letter-spacing: 1px; text-transform: uppercase; }

/* CTA portal */
.portal-strip { background: transparent; border: none;
                padding: 18px 40px;
                display: flex; align-items: center;
                justify-content: space-between; gap: 16px; }
.portal-strip p { font-size: 12px; color: var(--text4);
                  font-family: 'DM Mono', monospace;
                  letter-spacing: .3px; line-height: 1.6; }
.portal-btn { font-family: 'Outfit', sans-serif; font-size: 12px;
              font-weight: 500; color: var(--text);
              text-decoration: none; background: var(--surface);
              border: 1px solid var(--border2);
              padding: 8px 18px; border-radius: 6px;
              white-space: nowrap; flex-shrink: 0; }

/* Séparateurs de section */
.grp { padding: 26px 0 16px; }
.grp-label { font-family: 'DM Mono', monospace; font-size: 0.7rem;
              letter-spacing: 1.5px; text-transform: uppercase;
              color: #2a9d8f;
              border-left: 3px solid #2a9d8f; padding-left: 10px; }

/* Cards articles */
.card { background: var(--surface); border: 1px solid var(--border);
         border-radius: 10px; padding: 24px 28px 22px;
         margin-bottom: 10px; }
.card-top { display: flex; align-items: center; gap: 7px;
             margin-bottom: 12px; flex-wrap: wrap; }
.prio { font-family: 'DM Mono', monospace; font-size: 10px;
         font-weight: 400; letter-spacing: .3px; }
.prio.h { color: #e05252; }
.prio.m { color: #d4921a; }
.prio.l { color: #2a9d7a; }
.card-date { font-family: 'DM Mono', monospace; font-size: 10px;
              color: var(--text5); }

/* Catégories */
.cat { font-family: 'DM Mono', monospace; font-size: 11px;
        letter-spacing: .5px; text-transform: uppercase;
        padding: 3px 9px; border-radius: 3px; font-weight: 500; }
.cat-therapeutique    { background: rgba(147,51,234,.08);  color: #9333ea;
                         border: 0.5px solid rgba(147,51,234,.25); }
.cat-clinique         { background: rgba(107,159,212,.08); color: #6b9fd4;
                         border: 0.5px solid rgba(107,159,212,.25); }
.cat-exercice         { background: rgba(74,158,187,.08);  color: #4a9ebb;
                         border: 0.5px solid rgba(74,158,187,.25); }

.card-title { font-family: 'Instrument Serif', Georgia, serif;
               font-size: 19px; font-weight: 400; color: var(--text);
               line-height: 1.35; margin-bottom: 10px; }
.card-resume { font-size: 13px; font-weight: 300; color: var(--text3);
                line-height: 1.7; margin-bottom: 12px; }
.card-impact { font-size: 12px; color: var(--text3); line-height: 1.65;
                padding: 10px 14px; margin-bottom: 14px;
                background: var(--impact); border-radius: 4px;
                font-weight: 300; border: 1px solid var(--border); }
.card-link { font-family: 'Outfit', sans-serif; font-size: 12px;
              font-weight: 500; color: var(--text2);
              text-decoration: none; border: 1px solid var(--border2);
              padding: 6px 16px; border-radius: 6px;
              display: inline-block; }

/* Footer */
.footer { padding: 24px 0 8px; text-align: center; }
.footer p { font-family: 'DM Mono', monospace; font-size: 10px;
             color: var(--text5); letter-spacing: .4px; line-height: 2; }
.footer a { color: var(--text5); }
"""

# ---------------------------------------------------------------------------
# Rendu d'un article
# ---------------------------------------------------------------------------

def _render_article(item: dict[str, Any]) -> str:
    tri = item.get("tri_json") or {}
    score = item.get("score_density") or 5
    prio_label, prio_class = _priority_label(score)

    date_str = _format_date(item.get("official_date") or "")

    cat = item.get("categorie") or ""
    cat_label, cat_class = CAT_STYLES.get(cat, ("", ""))

    titre = tri.get("titre_court") or item.get("title_raw") or ""
    resume = tri.get("resume") or ""
    impact = tri.get("impact_pratique") or ""
    url = item.get("official_url") or "#"

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
    <span class="prio {prio_class}">{_he(prio_label)}</span>
    <span class="card-date">{_he(date_str)}</span>
    {cat_html}
  </div>
  <div class="card-title">{_he(titre)}</div>
  <p class="card-resume">{_he(resume)}</p>
  {impact_html}
  <a class="card-link" href="{url}">Lire le texte officiel →</a>
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
    all_items = items_spec + items_transv

    n_alertes = sum(
        1 for i in all_items
        if (i.get("tri_json") or {}).get("nature", "") in ("ALERTE", "RECOMMANDATION")
    )
    n_autres = n_total - n_alertes

    mois = MOIS_FR_LONG[emission_date.month]

    # Trouver l'item le plus urgent pour ancrer l'édito
    all_items_sorted = sorted(all_items, key=lambda x: x.get("score_density") or 0, reverse=True)
    top = all_items_sorted[0] if all_items_sorted else None
    top_titre = (top.get("tri_json") or {}).get("titre_court") or "" if top else ""
    top_impact = (top.get("tri_json") or {}).get("impact_pratique") or "" if top else ""

    if top_titre and top_impact:
        # Édito ancré sur l'essentiel
        intro = f"Ce {mois}, l'essentiel\u00a0: {top_titre.rstrip('.')}."
        detail = f" {top_impact}" if top_impact else ""
        if n_total > 1:
            suite = f" Puis {n_total - 1} autre{'s' if n_total > 2 else ''} texte{'s' if n_total > 2 else ''} triés par urgence."
        else:
            suite = ""
        return f"{intro}{detail}{suite}"
    elif n_alertes > 0 and n_autres > 0:
        contenu = (
            f"{n_autres} recommandation{'s' if n_autres > 1 else ''} "
            f"et {n_alertes} alerte{'s' if n_alertes > 1 else ''} de sécurité"
        )
    elif n_alertes > 0:
        contenu = f"{n_alertes} alerte{'s' if n_alertes > 1 else ''} de sécurité"
    else:
        contenu = f"{n_autres} texte{'s' if n_autres > 1 else ''} réglementaire{'s' if n_autres > 1 else ''}"

    return (
        f"Ce mois de {mois}, {n_total} texte{'s' if n_total > 1 else ''} "
        f"sélectionnés pour votre pratique de {specialty_name}\u00a0: {contenu}."
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
        f"MedNews — Veille réglementaire {specialty_name}",
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

def build_newsletter(
    specialty_slug: str,
    items: list[dict[str, Any]],
    emission_date: date | None = None,
    portal_url: str = "",
    unsubscribe_url: str = "{{unsubscribe_url}}",
    archive_url: str = "{{archive_url}}",
) -> tuple[str, str, str]:
    """
    Construit la newsletter.

    Args:
        specialty_slug  : slug de la spécialité
        items           : liste mixte (spécialité + transversaux)
        emission_date   : date d'émission (défaut: aujourd'hui)
        portal_url      : URL du portal (construit depuis BASE_URL si vide)
        unsubscribe_url : URL de désabonnement
        archive_url     : URL d'archive

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

    specialty_name = SPECIALTY_LABELS.get(specialty_slug, specialty_slug) or "Médecine libérale"
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

    # Séparer articles spécialité / transversaux
    # IMPORTANT : on filtre par specialites[] (liste LLM) ET specialty_slug (colonne DB),
    # PAS par audience=="SPECIALITE" seul — sinon des items d'autres spécialités
    # (ex: chirurgie-vasculaire) passent dans toutes les newsletters SPECIALITE.
    items_spec = [
        i for i in items
        if specialty_slug in (i.get("specialites") or [])
        or i.get("specialty_slug") == specialty_slug
    ]
    n_total = len(items_spec)
    n_alertes = sum(
        1 for i in items_spec
        if (i.get("tri_json") or {}).get("nature", "") in ("ALERTE", "RECOMMANDATION")
    )
    n_autres = n_total - n_alertes

    # Sujet : accroche sur l'item le plus urgent (score le plus élevé)
    all_sorted = sorted(items_spec, key=lambda x: x.get("score_density") or 0, reverse=True)
    top_item = all_sorted[0] if all_sorted else None
    if top_item:
        top_titre = (top_item.get("tri_json") or {}).get("titre_court") or top_item.get("title_raw") or ""
        # Tronquer à ~50 chars pour éviter coupure client email
        if len(top_titre) > 52:
            top_titre = top_titre[:50].rsplit(" ", 1)[0] + "…"
        if n_alertes >= 2:
            sujet = f"[MedNews] {top_titre} · {n_alertes} alertes {specialty_name}"
        elif n_alertes == 1:
            sujet = f"[MedNews] {top_titre} · {n_total} texte{'s' if n_total > 1 else ''} {specialty_name}"
        else:
            sujet = f"[MedNews] {top_titre} · {n_total} reco{'s' if n_total > 1 else ''} {specialty_name}"
    else:
        sujet = f"[MedNews] {specialty_name} — Veille {MOIS_FR_LONG[emission_date.month]} {emission_date.year}"

    edito_text = _generate_edito(items_spec, [], specialty_name, emission_date)

    # Articles spécialité
    articles_specialite_html = (
        "".join(_render_article(i) for i in items_spec)
        if items_spec
        else '<p style="color:var(--text5);font-style:italic;padding:20px 0;">Aucun article ce mois-ci.</p>'
    )

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_he(sujet)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="bg">
<div class="wrap">

  <!-- MASTHEAD -->
  <div class="masthead">
    <div class="masthead-name">Med<em>News</em></div>
    <div class="masthead-sub">Veille réglementaire · Médecine libérale</div>
  </div>

  <!-- HEADER -->
  <div class="hd">
    <div class="hd-eye">
      <span class="hd-dot"></span>Veille réglementaire
    </div>
    <div class="hd-title">
      {_he(specialty_name)}<br><em>{_he(mois_annee)}</em>
    </div>
    <div class="hd-stats">
      <span class="n">{n_total}</span> texte{'s' if n_total != 1 else ''}
      <span class="sep">·</span>
      <span class="n">{n_alertes}</span> alerte{'s' if n_alertes != 1 else ''}
      <span class="sep">·</span>
      <span class="n">{n_autres}</span> arrêté{'s' if n_autres != 1 else ''}/reco
      <span class="sep">·</span>JORF · ANSM · HAS
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
    <a class="portal-btn" href="{portal_url}">Accéder à mon espace →</a>
  </div>

  <!-- ARTICLES SPÉCIALITÉ -->
  <div class="grp">
    <div class="grp-label">{_he(specialty_name)}</div>
  </div>

  {articles_specialite_html}

  <!-- FOOTER -->
  <div class="footer">
    <p>
      Abonné à MedNews ·
      <a href="{unsubscribe_url}">Se désabonner</a> ·
      <a href="{archive_url}">Voir en ligne</a><br>
      MedNews — Veille réglementaire pour médecins libéraux
    </p>
  </div>

</div>
</div>
</body>
</html>"""

    plain = _build_plain(specialty_name, items_spec, [], portal_url)

    return sujet, html, plain
