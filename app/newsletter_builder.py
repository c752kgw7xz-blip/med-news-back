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
    "medicament":           ("Médicaments",      "cat-medicament"),
    "clinique":             ("Clinique",          "cat-clinique"),
    "dispositifs_medicaux": ("Dispositifs méd.",  "cat-dispositifs"),
    "facturation":          ("Facturation",       "cat-facturation"),
    "administratif":        ("Administratif",     "cat-administratif"),
    "sante_publique":       ("Santé publique",    "cat-sante_publique"),
    "exercice":             ("Exercice libéral",  "cat-exercice"),
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

/* Header */
.hd { background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px 10px 0 0; padding: 36px 40px 30px; }
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
.hd-meta { display: flex; align-items: center; gap: 14px; margin-top: 14px; }
.hd-chip { font-family: 'DM Mono', monospace; font-size: 10px;
            color: var(--text5); letter-spacing: .5px; }
.hd-sep  { width: 1px; height: 10px; background: var(--border); }

/* Édito */
.edito { background: var(--surface); border: 1px solid var(--border);
          border-top: none; padding: 24px 40px 26px; }
.edito p { font-size: 13px; color: var(--text3); line-height: 1.85; }
.edito-sign { font-family: 'DM Mono', monospace; font-size: 10px;
               color: var(--text5); margin-top: 12px;
               letter-spacing: 1px; text-transform: uppercase; }

/* CTA portal */
.portal-strip { background: var(--strip); border: 1px solid var(--border);
                border-top: none; padding: 18px 40px;
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
.grp { padding: 26px 0 8px; display: flex;
        align-items: center; gap: 10px; }
.grp-dot { width: 5px; height: 5px; border-radius: 50%;
            background: var(--border2); flex-shrink: 0; }
.grp-label { font-family: 'DM Mono', monospace; font-size: 10px;
              letter-spacing: 1.5px; text-transform: uppercase;
              color: var(--text5); }
.grp-line { flex: 1; height: 1px; background: var(--border); }

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
.cat { font-family: 'DM Mono', monospace; font-size: 9px;
        letter-spacing: .5px; text-transform: uppercase;
        padding: 2px 7px; border-radius: 2px; }
.cat-medicament       { background: rgba(160,123,224,.08); color: #a07be0;
                         border: 0.5px solid rgba(160,123,224,.25); }
.cat-clinique         { background: rgba(107,159,212,.08); color: #6b9fd4;
                         border: 0.5px solid rgba(107,159,212,.25); }
.cat-dispositifs      { background: rgba(91,168,207,.08);  color: #5ba8cf;
                         border: 0.5px solid rgba(91,168,207,.25); }
.cat-facturation      { background: rgba(212,146,26,.08);  color: #d4921a;
                         border: 0.5px solid rgba(212,146,26,.25); }
.cat-administratif    { background: rgba(192,106,170,.08); color: #c06aaa;
                         border: 0.5px solid rgba(192,106,170,.25); }
.cat-sante_publique   { background: rgba(42,157,122,.08);  color: #2a9d7a;
                         border: 0.5px solid rgba(42,157,122,.25); }
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

    if n_alertes > 0 and n_autres > 0:
        contenu = (
            f"{n_autres} arrêté{'s' if n_autres > 1 else ''}"
            f"/recommandation{'s' if n_autres > 1 else ''} "
            f"et {n_alertes} alerte{'s' if n_alertes > 1 else ''} de sécurité"
        )
    elif n_alertes > 0:
        contenu = f"{n_alertes} alerte{'s' if n_alertes > 1 else ''} de sécurité"
    else:
        contenu = (
            f"{n_autres} texte{'s' if n_autres > 1 else ''} "
            f"réglementaire{'s' if n_autres > 1 else ''}"
        )

    return (
        f"Ce mois de {mois}, {n_total} texte{'s' if n_total > 1 else ''} "
        f"à impact direct sur votre pratique de {specialty_name}\u00a0: "
        f"{contenu}. "
        f"Aucun article ne devrait vous prendre plus de deux minutes."
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

    if not portal_url:
        base = os.environ.get("BASE_URL", "").rstrip("/")
        portal_url = f"{base}/portal" if base else "#"

    specialty_name = SPECIALTY_LABELS.get(specialty_slug, specialty_slug) or "Médecine libérale"
    mois_annee = f"{MOIS_FR_LONG[emission_date.month].capitalize()} {emission_date.year}"

    # Séparer articles spécialité / transversaux
    items_spec = [
        i for i in items
        if i.get("specialty_slug") == specialty_slug or i.get("audience") == "SPECIALITE"
    ]
    items_transv = [
        i for i in items
        if i.get("audience") in ("TRANSVERSAL_LIBERAL", "PHARMACIENS")
        and (i.get("score_density") or 0) >= 8
        and i not in items_spec
    ]
    # Max 2 transversaux
    items_transv = sorted(items_transv, key=lambda x: x.get("score_density") or 0, reverse=True)[:2]

    n_total = len(items_spec) + len(items_transv)
    n_alertes = sum(
        1 for i in items_spec + items_transv
        if (i.get("tri_json") or {}).get("nature", "") in ("ALERTE", "RECOMMANDATION")
    )
    n_autres = n_total - n_alertes

    sujet = (
        f"[MedNews] {specialty_name} — Veille réglementaire "
        f"{MOIS_FR_LONG[emission_date.month]} {emission_date.year} "
        f"({n_total} texte{'s' if n_total > 1 else ''})"
    )

    edito_text = _generate_edito(items_spec, items_transv, specialty_name, emission_date)

    # Articles spécialité
    articles_specialite_html = (
        "".join(_render_article(i) for i in items_spec)
        if items_spec
        else '<p style="color:var(--text5);font-style:italic;padding:20px 0;">Aucun article ce mois-ci.</p>'
    )

    # Section transversal (conditionnelle)
    if items_transv:
        articles_transv_html = "".join(_render_article(i) for i in items_transv)
        section_transversal_html = f"""
<div class="grp">
  <div class="grp-dot"></div>
  <div class="grp-label">Tous les médecins libéraux</div>
  <div class="grp-line"></div>
</div>
{articles_transv_html}
"""
    else:
        section_transversal_html = ""

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

  <!-- HEADER -->
  <div class="hd">
    <div class="hd-eye">
      <span class="hd-dot"></span>Veille réglementaire · MedNews
    </div>
    <div class="hd-title">
      {_he(specialty_name)}<br><em>{_he(mois_annee)}</em>
    </div>
    <div class="hd-meta">
      <span class="hd-chip">{n_total} textes</span>
      <div class="hd-sep"></div>
      <span class="hd-chip">{n_alertes} alerte{'s' if n_alertes != 1 else ''} · {n_autres} arrêté{'s' if n_autres != 1 else ''}/reco</span>
      <div class="hd-sep"></div>
      <span class="hd-chip">JORF · ANSM · HAS</span>
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
    <div class="grp-dot"></div>
    <div class="grp-label">{_he(specialty_name)}</div>
    <div class="grp-line"></div>
  </div>

  {articles_specialite_html}

  <!-- ARTICLES TRANSVERSAUX (si présents) -->
  {section_transversal_html}

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

    plain = _build_plain(specialty_name, items_spec, items_transv, portal_url)

    return sujet, html, plain
