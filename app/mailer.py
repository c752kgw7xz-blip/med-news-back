# app/mailer.py
"""
Envoi des newsletters par email.

Priorité :
  1. SendGrid API (SENDGRID_API_KEY défini)
  2. SMTP générique (SMTP_HOST défini) — fallback ou dev local

Variables d'environnement :
  SENDGRID_API_KEY     clé API SendGrid
  MAIL_FROM            expéditeur   (ex: newsletter@mednews.fr)
  MAIL_FROM_NAME       nom affiché  (ex: MedNews)

  # Fallback SMTP
  SMTP_HOST            ex: smtp.gmail.com
  SMTP_PORT            défaut 587
  SMTP_USER
  SMTP_PASSWORD
  SMTP_USE_TLS         true | false (défaut true)
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import NamedTuple

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class MailResult(NamedTuple):
    success: bool
    recipient: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Helpers config
# ---------------------------------------------------------------------------

def _from_address() -> tuple[str, str]:
    addr = os.environ.get("MAIL_FROM", "newsletter@mednews.fr")
    name = os.environ.get("MAIL_FROM_NAME", "MedNews")
    return addr, name


# ---------------------------------------------------------------------------
# Envoi via SendGrid
# ---------------------------------------------------------------------------

def _send_sendgrid(
    to_email: str,
    subject: str,
    html: str,
    plain: str,
) -> MailResult:
    api_key = "".join(os.environ["SENDGRID_API_KEY"].split())
    from_addr, from_name = _from_address()

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_addr, "name": from_name},
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
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        if r.status_code in (200, 202):
            return MailResult(success=True, recipient=to_email)
        return MailResult(
            success=False,
            recipient=to_email,
            error=f"SendGrid HTTP {r.status_code}: {r.text[:200]}",
        )
    except Exception as e:
        return MailResult(success=False, recipient=to_email, error=str(e))


# ---------------------------------------------------------------------------
# Envoi via SMTP
# ---------------------------------------------------------------------------

def _send_smtp(
    to_email: str,
    subject: str,
    html: str,
    plain: str,
) -> MailResult:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"
    from_addr, from_name = _from_address()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        ctx = ssl.create_default_context() if use_tls else None
        with smtplib.SMTP(host, port, timeout=30) as s:
            if use_tls:
                s.ehlo()
                s.starttls(context=ctx)
            if user:
                s.login(user, password)
            s.sendmail(from_addr, to_email, msg.as_string())
        return MailResult(success=True, recipient=to_email)
    except Exception as e:
        return MailResult(success=False, recipient=to_email, error=str(e))


# ---------------------------------------------------------------------------
# Interface publique
# ---------------------------------------------------------------------------

def send_email(
    to_email: str,
    subject: str,
    html: str,
    plain: str,
) -> MailResult:
    """
    Envoie un email. Choisit automatiquement SendGrid ou SMTP.
    """
    if os.environ.get("SENDGRID_API_KEY"):
        logger.debug("Envoi via SendGrid")
        return _send_sendgrid(to_email, subject, html, plain)

    if os.environ.get("SMTP_HOST"):
        logger.debug("Envoi via SMTP")
        return _send_smtp(to_email, subject, html, plain)

    raise RuntimeError(
        "Aucun transport email configuré. "
        "Définir SENDGRID_API_KEY ou SMTP_HOST dans l'environnement."
    )


def send_bulk(
    recipients: list[str],
    subject: str,
    html: str,
    plain: str,
) -> dict:
    """
    Envoie à une liste de destinataires. Retourne un rapport.
    """
    ok = []
    errors = []
    for email in recipients:
        result = send_email(email, subject, html, plain)
        if result.success:
            ok.append(email)
        else:
            # On inclut l'email dans errors pour que l'admin puisse investiguer,
            # mais on ne le loggue pas en clair (évite la fuite PII dans les logs)
            errors.append({"email": email, "error": result.error})
            redacted = email[:2] + "***@***" if "@" in email else "***"
            logger.error("Échec envoi %s : %s", redacted, result.error)

    return {"sent": len(ok), "failed": len(errors), "errors": errors}
