"""
Traite la queue pending_emails et envoie les emails via SendGrid.
Appelé par le cron GitHub Actions toutes les 10 minutes.
"""
import os
import sys
import time
import logging
import psycopg2
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DB = os.environ["DATABASE_URL"]
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "newsletter@mednews.fr")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "MedNews")

if not SENDGRID_API_KEY:
    logger.error("SENDGRID_API_KEY non défini — abandon")
    sys.exit(1)


def _send(to_email: str, subject: str, html: str, plain: str) -> tuple[bool, str]:
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": MAIL_FROM, "name": MAIL_FROM_NAME},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": plain},
            {"type": "text/html", "value": html},
        ],
    }
    try:
        r = httpx.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
            timeout=30,
        )
        if r.status_code in (200, 202):
            return True, ""
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def main():
    conn = psycopg2.connect(DB)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, to_email, subject, html_body, plain_body
        FROM pending_emails
        WHERE sent_at IS NULL AND attempts < max_attempts
        ORDER BY created_at
        LIMIT 50
    """)
    rows = cur.fetchall()

    if not rows:
        logger.info("Aucun email en attente")
        conn.close()
        return

    logger.info("%d email(s) en attente", len(rows))
    sent = failed = 0

    for email_id, to_email, subject, html, plain in rows:
        success, error = _send(to_email, subject, html, plain)
        if success:
            cur.execute(
                "UPDATE pending_emails SET sent_at = NOW() WHERE id = %s",
                (email_id,)
            )
            sent += 1
            logger.info("Envoyé → %s", to_email[:3] + "***")
        else:
            cur.execute(
                "UPDATE pending_emails SET attempts = attempts + 1, last_error = %s WHERE id = %s",
                (error, email_id)
            )
            failed += 1
            logger.error("Échec → %s : %s", to_email[:3] + "***", error)
        conn.commit()
        time.sleep(0.2)  # Évite le rate-limit SendGrid

    conn.close()
    logger.info("Terminé — envoyés: %d, échecs: %d", sent, failed)
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
