#!/usr/bin/env python3
"""
Envoie un email de relance aux utilisateurs beta sans abonnement Stripe actif.

Usage :
  python3 scripts/send_beta_end_reminder.py          # mode dry-run (affiche les destinataires)
  python3 scripts/send_beta_end_reminder.py --send   # envoi réel

À planifier mi-juillet (ex. 14 juillet 2026).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import argparse
from datetime import datetime, timezone

import psycopg2

from app.mailer import send_email
from app.security import decrypt_email, make_unsubscribe_token

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BETA_END = datetime(2026, 8, 1, tzinfo=timezone.utc)
BASE_URL  = os.environ.get("BASE_URL", "https://med-news.fr")

SUBJECT = "Votre accès MedNews gratuit se termine le 1er août"


def _load_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("DATABASE_URL="):
                    return line.split("=", 1)[1].strip("\"'")
    raise RuntimeError("DATABASE_URL introuvable")


# ---------------------------------------------------------------------------
# Destinataires : users actifs sans abonnement Stripe valide
# ---------------------------------------------------------------------------

def _get_recipients() -> list[dict]:
    """Retourne les users beta sans abonnement actif (hors étudiants)."""
    conn = psycopg2.connect(_load_db_url(), connect_timeout=15)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, email_ciphertext, first_name, specialty_id
            FROM users
            WHERE is_active = TRUE
              AND plan != 'student'
              AND (
                stripe_subscription_id IS NULL
                OR subscribed_until IS NULL
                OR subscribed_until < NOW()
              )
            ORDER BY created_at
        """)
        rows = cur.fetchall()
    finally:
        conn.close()

    recipients = []
    for row in rows:
        try:
            email = decrypt_email(row[1])
        except Exception:
            continue
        recipients.append({
            "id":         str(row[0]),
            "email":      email,
            "first_name": row[2] or "Docteur",
            "specialty":  row[3] or "",
        })
    return recipients


# ---------------------------------------------------------------------------
# Template email
# ---------------------------------------------------------------------------

def _build_html(first_name: str, user_id: str) -> str:
    subscribe_url = f"{BASE_URL}/signup"
    token = make_unsubscribe_token(user_id)
    unsub_url = f"{BASE_URL}/unsubscribe?user_id={user_id}&token={token}"
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{SUBJECT}</title>
</head>
<body style="margin:0;padding:0;background:#F9F7F4;font-family:'Outfit',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F9F7F4;padding:40px 0;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#FFFFFF;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">

      <!-- Header -->
      <tr>
        <td style="background:#1A1A2E;padding:28px 40px;">
          <span style="font-size:22px;font-weight:700;color:#FFFFFF;letter-spacing:-0.5px;">Med<span style="color:#7C9EFF;">News</span></span>
          <span style="font-size:12px;color:rgba(255,255,255,.5);margin-left:12px;">Votre veille médicale</span>
        </td>
      </tr>

      <!-- Body -->
      <tr>
        <td style="padding:40px 40px 32px;">
          <p style="font-size:16px;color:#1A1A2E;margin:0 0 20px;">Bonjour {first_name},</p>

          <p style="font-size:15px;color:#3D3D3D;line-height:1.7;margin:0 0 16px;">
            Depuis votre inscription, vous bénéficiez d'un accès gratuit à MedNews dans le cadre de notre phase bêta.
            <strong>Cet accès prend fin le 1er août 2026.</strong>
          </p>

          <p style="font-size:15px;color:#3D3D3D;line-height:1.7;margin:0 0 28px;">
            Pour continuer à recevoir votre veille réglementaire et scientifique personnalisée par spécialité,
            souscrivez avant le 1er août. Vous bénéficierez d'une <strong>période d'essai gratuite de 30 jours</strong>
            — aucun débit avant le 1er septembre.
          </p>

          <!-- CTA -->
          <table cellpadding="0" cellspacing="0" style="margin:0 0 32px;">
            <tr>
              <td style="background:#3B52A4;border-radius:8px;">
                <a href="{subscribe_url}"
                   style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:600;color:#FFFFFF;text-decoration:none;letter-spacing:0.2px;">
                  S'abonner avant le 1er août →
                </a>
              </td>
            </tr>
          </table>

          <!-- Ce que vous gardez -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#F4F6FF;border-radius:8px;padding:20px 24px;margin-bottom:28px;">
            <tr>
              <td>
                <p style="font-size:13px;font-weight:600;color:#3B52A4;margin:0 0 10px;text-transform:uppercase;letter-spacing:0.5px;">
                  Ce que vous continuez à recevoir
                </p>
                <ul style="margin:0;padding-left:18px;font-size:14px;color:#3D3D3D;line-height:1.8;">
                  <li>Veille réglementaire ANSM, HAS, EMA, JORF — filtrée par spécialité</li>
                  <li>Études cliniques et méta-analyses practice-changing</li>
                  <li>Recommandations des sociétés savantes</li>
                  <li>Alertes de sécurité et nouvelles AMM</li>
                </ul>
              </td>
            </tr>
          </table>

          <p style="font-size:13px;color:#888;line-height:1.6;margin:0;">
            Si vous avez déjà souscrit un abonnement, ignorez ce message — votre accès est assuré.
            Pour toute question : <a href="mailto:contact@med-news.fr" style="color:#3B52A4;">contact@med-news.fr</a>
          </p>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#F4F4F4;padding:20px 40px;border-top:1px solid #E8E8E8;">
          <p style="font-size:12px;color:#999;margin:0;line-height:1.6;">
            MedNews · Veille médicale personnalisée pour professionnels de santé<br>
            <a href="{unsub_url}" style="color:#999;">Se désabonner</a>
          </p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""


def _build_plain(first_name: str, user_id: str) -> str:
    token = make_unsubscribe_token(user_id)
    return f"""Bonjour {first_name},

Votre accès gratuit MedNews (phase bêta) se termine le 1er août 2026.

Pour continuer à recevoir votre veille médicale personnalisée par spécialité, souscrivez avant le 1er août. Vous bénéficierez d'une période d'essai gratuite de 30 jours — aucun débit avant le 1er septembre.

S'abonner : {BASE_URL}/signup

Ce que vous continuez à recevoir :
- Veille réglementaire ANSM, HAS, EMA, JORF filtrée par spécialité
- Études cliniques et méta-analyses practice-changing
- Recommandations des sociétés savantes
- Alertes de sécurité et nouvelles AMM

Si vous avez déjà souscrit un abonnement, ignorez ce message.
Pour toute question : contact@med-news.fr

Se désabonner : {BASE_URL}/unsubscribe?user_id={user_id}&token={token}

— L'équipe MedNews
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Email de relance fin bêta MedNews")
    parser.add_argument("--send", action="store_true", help="Envoi réel (sans ce flag = dry-run)")
    args = parser.parse_args()

    recipients = _get_recipients()
    print(f"Destinataires trouvés : {len(recipients)}")

    if not args.send:
        print("\n[DRY-RUN] Aucun email envoyé. Destinataires :")
        for r in recipients:
            print(f"  - {r['email']} ({r['first_name']}, {r['specialty'] or 'spé inconnue'})")
        print("\nRelancer avec --send pour envoyer.")
        return

    ok = 0
    errors = 0
    for r in recipients:
        html  = _build_html(r["first_name"], r["id"])
        plain = _build_plain(r["first_name"], r["id"])
        result = send_email(r["email"], SUBJECT, html, plain)
        if result.success:
            ok += 1
            print(f"  ✓ {r['email']}")
        else:
            errors += 1
            print(f"  ✗ {r['email']} — {result.error}")

    print(f"\nRésultat : {ok} envoyés, {errors} échecs")


if __name__ == "__main__":
    main()
