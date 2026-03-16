# app/newsletter_builder.py
"""
Construit le HTML de la newsletter pour une spécialité donnée.

Entrée  : liste d'items APPROVED pour cette spécialité (depuis DB)
Sortie  : (sujet_email: str, html: str, texte_plain: str)

Design :
  - Email responsive, lisible sur mobile
  - Chaque article = carte avec titre court, résumé, score visuel, lien officiel
  - Ordre : score_density DESC (les plus importants en premier)
  - Séparation visuelle TRANSVERSAL / SPECIALITE si les deux présents
"""

from __future__ import annotations

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

MONTH_FR = [
    "", "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
]


def _month_label(d: date) -> str:
    return f"{MONTH_FR[d.month]} {d.year}"


def _score_dots(score: int) -> str:
    """Retourne des pastilles visuelles selon le score (1-10)."""
    filled = min(score, 10)
    empty = 10 - filled
    return (
        '<span style="color:#1D9E75;font-size:11px;letter-spacing:2px;">'
        + "●" * filled
        + '</span>'
        + '<span style="color:#D3D1C7;font-size:11px;letter-spacing:2px;">'
        + "●" * empty
        + "</span>"
    )


def _score_label(score: int) -> tuple[str, str]:
    """Retourne (label texte, couleur hex) selon le score."""
    if score >= 8:
        return "À lire impérativement", "#A32D2D"
    if score >= 5:
        return "Important", "#854F0B"
    return "Informatif", "#3B6D11"


def _nature_badge(nature: str) -> str:
    colors = {
        "LOI": ("#042C53", "#E6F1FB"),
        "DECRET": ("#26215C", "#EEEDFE"),
        "ARRETE": ("#085041", "#E1F5EE"),
        "ORDONNANCE": ("#4A1B0C", "#FAECE7"),
    }
    bg, fg = colors.get(nature.upper(), ("#444441", "#F1EFE8"))
    return (
        f'<span style="background:{fg};color:{bg};padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:500;'
        f'text-transform:uppercase;letter-spacing:.5px;">{nature}</span>'
    )


# ---------------------------------------------------------------------------
# Rendu d'un article
# ---------------------------------------------------------------------------

def _render_article(item: dict[str, Any], idx: int) -> str:
    tri = item.get("tri_json") or {}
    lecture = item.get("lecture_json") or {}

    titre_court = _he(tri.get("titre_court") or item.get("title_raw", "Sans titre")[:80])
    resume = _he(tri.get("resume", ""))
    impact = _he(tri.get("impact_pratique", ""))
    nature = _he(tri.get("nature", ""))
    date_pub = tri.get("date_publication", item.get("official_date", ""))
    official_url = item.get("official_url", "#")
    score = item.get("score_density", 5)
    points = lecture.get("points_cles", [])

    score_txt, score_color = _score_label(score)

    # Points clés (max 4)
    points_html = ""
    if points:
        items_html = "".join(
            f'<li style="margin:4px 0;color:#3d3d3a;">{_he(p)}</li>'
            for p in points[:4]
        )
        points_html = f'<ul style="margin:10px 0 0 0;padding-left:18px;">{items_html}</ul>'

    nature_badge = _nature_badge(nature) if nature else ""
    dots = _score_dots(score)

    # Séparateur entre articles
    separator = '<hr style="border:none;border-top:1px solid #e8e6df;margin:24px 0;">' if idx > 0 else ""

    return f"""
{separator}
<div style="margin-bottom:8px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
    {nature_badge}
    <span style="font-size:11px;color:#888780;">{date_pub}</span>
    <span style="font-size:11px;font-weight:500;color:{score_color};">
      {score_txt}
    </span>
  </div>
  <h3 style="margin:0 0 8px 0;font-size:17px;font-weight:600;
             color:#2C2C2A;line-height:1.35;">
    {titre_court}
  </h3>
  <div style="margin-bottom:4px;">{dots}</div>
  <p style="margin:10px 0 0 0;font-size:14px;color:#3d3d3a;line-height:1.6;">
    {resume}
  </p>
  {f'<p style="margin:8px 0 0 0;font-size:13px;color:#5F5E5A;font-style:italic;line-height:1.5;border-left:3px solid #1D9E75;padding-left:10px;">{impact}</p>' if impact else ""}
  {points_html}
  <div style="margin-top:12px;">
    <a href="{official_url}"
       style="font-size:13px;color:#185FA5;text-decoration:none;font-weight:500;">
      Lire le texte officiel →
    </a>
  </div>
</div>
"""


# ---------------------------------------------------------------------------
# Assemblage de l'email complet
# ---------------------------------------------------------------------------

def build_newsletter(
    specialty_slug: str | None,
    items: list[dict[str, Any]],
    emission_date: date | None = None,
) -> tuple[str, str, str]:
    """
    Construit la newsletter.

    Args:
        specialty_slug : slug de la spécialité (None = transversal seulement)
        items          : liste d'items APPROVED triés par score DESC
        emission_date  : date d'émission (défaut: aujourd'hui)

    Returns:
        (sujet: str, html: str, texte_plain: str)
    """
    if emission_date is None:
        emission_date = date.today()

    period = _month_label(emission_date)
    specialty_label = (
        SPECIALTY_LABELS.get(specialty_slug, specialty_slug)
        if specialty_slug
        else "Médecine libérale"
    )

    # Séparer transversal / spécialité
    transversal = [i for i in items if i.get("audience") == "TRANSVERSAL_LIBERAL"]
    specialite = [i for i in items if i.get("audience") == "SPECIALITE"]

    total = len(items)
    sujet = (
        f"[MedNews] {specialty_label} — Veille réglementaire {period} "
        f"({total} texte{'s' if total > 1 else ''})"
    )

    # ---- Sections HTML ----
    def section(titre: str, color: str, article_list: list) -> str:
        if not article_list:
            return ""
        articles_html = "".join(
            _render_article(item, i) for i, item in enumerate(article_list)
        )
        return f"""
<div style="margin-top:32px;">
  <div style="border-left:4px solid {color};padding-left:12px;margin-bottom:20px;">
    <h2 style="margin:0;font-size:15px;font-weight:600;
               color:#2C2C2A;text-transform:uppercase;
               letter-spacing:.8px;">{titre}</h2>
  </div>
  {articles_html}
</div>
"""

    section_transversal = section(
        "Tous les médecins libéraux", "#185FA5", transversal
    )
    section_specialite = section(
        specialty_label, "#1D9E75", specialite
    )

    if not transversal and not specialite:
        body_content = """
<p style="color:#888780;font-style:italic;text-align:center;padding:40px 0;">
  Aucun texte réglementaire notable ce mois-ci.
</p>
"""
    else:
        body_content = section_transversal + section_specialite

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{sujet}</title>
</head>
<body style="margin:0;padding:0;background:#f5f4ef;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">

  <!-- Wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0"
         style="background:#f5f4ef;padding:32px 16px;">
  <tr><td>
  <table width="600" cellpadding="0" cellspacing="0" align="center"
         style="max-width:600px;width:100%;">

    <!-- En-tête -->
    <tr>
      <td style="background:#2C2C2A;border-radius:10px 10px 0 0;
                 padding:28px 36px 24px;">
        <p style="margin:0;font-size:11px;font-weight:600;
                  color:#9FE1CB;letter-spacing:1.5px;
                  text-transform:uppercase;">Veille réglementaire</p>
        <h1 style="margin:6px 0 0;font-size:22px;font-weight:700;
                   color:#ffffff;line-height:1.3;">
          {specialty_label}
        </h1>
        <p style="margin:8px 0 0;font-size:13px;color:#B4B2A9;">
          {period} · {total} texte{'s' if total > 1 else ''} sélectionné{'s' if total > 1 else ''}
        </p>
      </td>
    </tr>

    <!-- Corps -->
    <tr>
      <td style="background:#ffffff;padding:32px 36px;
                 border-left:1px solid #e8e6df;border-right:1px solid #e8e6df;">
        {body_content}
      </td>
    </tr>

    <!-- Pied de page -->
    <tr>
      <td style="background:#f1efe8;border:1px solid #e8e6df;
                 border-top:none;border-radius:0 0 10px 10px;
                 padding:20px 36px;text-align:center;">
        <p style="margin:0;font-size:12px;color:#888780;line-height:1.7;">
          Vous recevez cet email car vous êtes abonné à MedNews ({specialty_label}).<br>
          <a href="{{{{unsubscribe_url}}}}"
             style="color:#888780;text-decoration:underline;">Se désabonner</a>
          &nbsp;·&nbsp;
          <a href="{{{{archive_url}}}}"
             style="color:#888780;text-decoration:underline;">Voir en ligne</a>
        </p>
        <p style="margin:8px 0 0;font-size:11px;color:#B4B2A9;">
          MedNews — Veille réglementaire pour médecins libéraux
        </p>
      </td>
    </tr>

  </table>
  </td></tr>
  </table>

</body>
</html>"""

    # ---- Texte plain ----
    plain_parts = [
        f"MEDNEWS — {specialty_label.upper()} — {period.upper()}",
        "=" * 60,
        "",
    ]
    for item in items:
        tri = item.get("tri_json") or {}
        titre = tri.get("titre_court") or item.get("title_raw", "")[:80]
        resume = tri.get("resume", "")
        url = item.get("official_url", "")
        score = item.get("score_density", 5)
        label, _ = _score_label(score)
        plain_parts += [
            f"[{label}] {titre}",
            resume,
            f"Lien : {url}",
            "",
        ]
    plain_parts += [
        "-" * 60,
        "MedNews — Veille réglementaire pour médecins libéraux",
    ]
    plain = "\n".join(plain_parts)

    return sujet, html, plain
